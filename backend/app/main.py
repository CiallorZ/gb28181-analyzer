#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GB28181 Analyzer — FastAPI 入口

API 统一前缀 /api/v1/，自动生成 OpenAPI 文档（/docs）。
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import ai, diagnostics, sessions, tasks
from .core.config import settings
from .core.db import init_db
from .core.security import origin_allowed
from .parsers import capture

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
log = logging.getLogger('gb28181')

app = FastAPI(
    title='GB28181 Analyzer',
    description='GB/T 28181 视联网协议分析与流媒体质量诊断平台',
    version='1.0.0-P0',
    docs_url='/api/v1/docs',
    openapi_url='/api/v1/openapi.json',
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# Origin 校验：状态变更请求若带 Origin，必须同源或在 CORS 白名单内。
# 无 body 的 POST（分析/取消/删除/清理）属于"简单请求"，浏览器不会预检，
# 仅靠 CORS 挡不住第三方页面发起的 CSRF。
_SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


@app.middleware('http')
async def _origin_guard(request: Request, call_next):
    if request.method not in _SAFE_METHODS:
        origin = request.headers.get('origin')
        if origin:
            hosts = [request.headers.get('host', '')]
            if request.headers.get('x-forwarded-host'):
                hosts.append(request.headers['x-forwarded-host'].split(',')[0].strip())
            protos = [request.url.scheme]
            if request.headers.get('x-forwarded-proto'):
                protos.append(request.headers['x-forwarded-proto'].split(',')[0].strip())
            if not origin_allowed(origin, hosts, protos, settings.CORS_ORIGINS):
                return JSONResponse(
                    status_code=403,
                    content={'error': '跨站请求被拒绝（Origin 不在允许范围）',
                             'status': 403})
    return await call_next(request)


# Host 头校验（防 DNS rebinding）。最后添加 = 最先执行。
if settings.ALLOWED_HOSTS and settings.ALLOWED_HOSTS != ['*']:
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=settings.ALLOWED_HOSTS)

API = '/api/v1'
app.include_router(tasks.router, prefix=API)
app.include_router(sessions.router, prefix=API)
app.include_router(diagnostics.router, prefix=API)
app.include_router(ai.router, prefix=API)


@app.on_event('startup')
def _startup():
    init_db()

    # 清理上次异常退出遗留的 analyzing 任务，否则会一直显示"分析中"
    from sqlalchemy import select as _select
    from .core.db import session_scope
    from .models.entities import AnalysisTask, TaskStatus
    try:
        with session_scope() as s:
            stale = s.scalars(_select(AnalysisTask).where(
                AnalysisTask.status == TaskStatus.ANALYZING)).all()
            for t in stale:
                t.status = TaskStatus.FAILED
                t.error_message = '分析进程中断（服务重启），请重新分析'
                t.stage = '已中断'
            if stale:
                log.warning('清理了 %d 个中断的分析任务', len(stale))
    except Exception as e:
        log.error('清理僵尸任务失败：%s', e)

    # 启动时按保留策略清理磁盘
    try:
        from .services import retention
        from .core.db import session_scope
        with session_scope() as _s:
            r = retention.auto_purge(_s)
        if r['actions']:
            log.info('启动清理：%d 个任务被清理，当前占用 %.1f MB',
                     len(r['actions']), r['usage']['total_mb'])
    except Exception as e:
        log.warning('启动清理失败：%s', e)

    log.info('数据库已就绪：%s', settings.DATABASE_URL)
    log.info('tshark: %s', capture.TSHARK or '未找到')
    log.info('ffmpeg: %s', capture.FFMPEG or '未找到')
    if not capture.TSHARK:
        log.warning('未找到 tshark，分析功能将不可用')


@app.get(API + '/health')
def health():
    """健康检查 —— 同时反映外部依赖状态"""
    return {
        'status': 'ok',
        'version': '1.0.0-P0',
        'dependencies': {
            'tshark': bool(capture.TSHARK),
            'ffmpeg': bool(capture.FFMPEG),
            'ffprobe': bool(capture.FFPROBE),
        },
        'tshark_path': capture.TSHARK,
        'ffmpeg_path': capture.FFMPEG,
        'database': settings.DATABASE_URL.split('://')[0],
    }


@app.get(API + '/rules')
def list_rules():
    """诊断规则清单 —— 前端展示与文档引用"""
    from .services.diagnosis import RULES
    return {'rules': [{'id': k, 'name': v} for k, v in RULES.items()],
            'total': len(RULES)}


# ---------------- 统一错误响应 ----------------
@app.exception_handler(StarletteHTTPException)
async def _http_err(_req: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={'error': exc.detail, 'status': exc.status_code},
    )


@app.exception_handler(RequestValidationError)
async def _validation_err(_req: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={'error': '请求参数无效', 'detail': exc.errors()},
    )


def run():
    import uvicorn
    uvicorn.run('app.main:app', host=settings.HOST, port=settings.PORT,
                reload=settings.DEBUG, log_level='info')


if __name__ == '__main__':
    run()
