#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M01 任务管理与文件上传"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.db import SessionLocal, get_db, session_scope
from ..core.security import looks_like_capture
from ..models.entities import (
    AnalysisTask, CaptureFile, DiagnosticEvent, TaskStatus, BusinessSession,
    MediaStream,
)
from ..services import analyzer
from ..schemas import task as S

router = APIRouter(prefix='/tasks', tags=['tasks'])

_running = {}
_run_lock = threading.Lock()


# ---------------------------------------------------------------
# 上传
# ---------------------------------------------------------------
@router.post('/upload', response_model=S.UploadResult, status_code=201)
async def upload_file(file: UploadFile = File(...),
                      db: Session = Depends(get_db)):
    """上传抓包文件并创建分析任务"""
    name = os.path.basename(file.filename or 'upload.pcap')
    ext = os.path.splitext(name)[1].lower()
    if ext not in settings.ALLOWED_EXT:
        raise HTTPException(400, '只支持 %s 格式' % '、'.join(settings.ALLOWED_EXT))

    limit = settings.MAX_UPLOAD_MB * 1024 * 1024
    uid = uuid.uuid4().hex[:16]
    safe = re.sub(r'[^\w.\-]', '_', name)[:80] or 'upload.pcap'
    dest = settings.UPLOAD_DIR / ('%s_%s' % (uid, safe))

    # 流式落盘，不整包进内存
    size = 0
    sha = hashlib.sha256()
    try:
        with open(dest, 'wb') as out:
            first = True
            while True:
                chunk = await file.read(1 << 20)
                if not chunk:
                    break
                if first:
                    first = False
                    # 文件头不是 pcap/pcapng 魔数就别往下写，避免落盘垃圾数据
                    if not looks_like_capture(chunk):
                        raise HTTPException(
                            400, '文件内容不是有效的 pcap/pcapng 抓包文件'
                                 '（文件头魔数不匹配）')
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, '文件超过 %d MB 上限'
                                        % settings.MAX_UPLOAD_MB)
                sha.update(chunk)
                out.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    except Exception as e:
        dest.unlink(missing_ok=True)
        raise HTTPException(500, '写入文件失败：%s' % e)

    if size == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, '上传的文件为空')

    task = AnalysisTask(
        name=name,
        status=TaskStatus.PENDING,
        configuration={},
    )
    db.add(task)
    db.flush()

    cf = CaptureFile(
        task_id=task.id, filename=name,
        stored_path=str(dest), file_size=size,
        file_format=ext.lstrip('.'), checksum=sha.hexdigest(),
    )
    db.add(cf)
    db.commit()
    db.refresh(task)

    return S.UploadResult(task_id=task.id, file_id=cf.id,
                          filename=name, size=size)


# ---------------------------------------------------------------
# 任务列表 / 详情
# ---------------------------------------------------------------
@router.get('', response_model=S.TaskList)
def list_tasks(page: int = 1, page_size: int = 20,
               status: str | None = None,
               keyword: str | None = None,
               db: Session = Depends(get_db)):
    page = max(1, page)
    page_size = min(100, max(1, page_size))

    stmt = select(AnalysisTask)
    if status:
        stmt = stmt.where(AnalysisTask.status == status)
    if keyword:
        stmt = stmt.where(AnalysisTask.name.contains(keyword))

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(AnalysisTask.created_at.desc())
        .offset((page - 1) * page_size).limit(page_size)
    ).all()

    return S.TaskList(
        total=total, page=page, page_size=page_size,
        items=[_task_brief(db, t) for t in rows],
    )


@router.get('/{task_id}', response_model=S.TaskDetail)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(AnalysisTask, task_id)
    if not task:
        raise HTTPException(404, '任务不存在')
    return _task_detail(db, task)


def _task_brief(db: Session, t: AnalysisTask) -> S.TaskBrief:
    cf = t.files[0] if t.files else None
    s = t.summary or {}
    return S.TaskBrief(
        id=t.id, name=t.name, status=t.status, progress=t.progress,
        stage=t.stage, created_at=t.created_at,
        file_size=cf.file_size if cf else None,
        packet_count=cf.packet_count if cf else None,
        duration=cf.duration if cf else None,
        session_count=s.get('session_count'),
        diagnostic_count=sum((s.get('diagnostics') or {}).values()) or None,
        error_message=t.error_message,
    )


def _task_detail(db: Session, t: AnalysisTask) -> S.TaskDetail:
    cf = t.files[0] if t.files else None
    return S.TaskDetail(
        id=t.id, name=t.name, status=t.status, progress=t.progress,
        stage=t.stage, created_at=t.created_at,
        started_at=t.started_at, completed_at=t.completed_at,
        error_message=t.error_message,
        configuration=t.configuration or {},
        summary=t.summary or {},
        file=S.FileInfo(
            id=cf.id, filename=cf.filename, file_size=cf.file_size,
            file_format=cf.file_format, checksum=cf.checksum,
            packet_count=cf.packet_count,
            capture_start=cf.capture_start, capture_end=cf.capture_end,
            duration=cf.duration, link_type=cf.link_type,
            ip_count=cf.ip_count, tcp_count=cf.tcp_count,
            udp_count=cf.udp_count, warnings=cf.warnings or [],
        ) if cf else None,
    )


# ---------------------------------------------------------------
# 启动 / 取消 / 删除
# ---------------------------------------------------------------
@router.post('/{task_id}/analyze', response_model=S.TaskBrief)
def start_analyze(task_id: int, bg: BackgroundTasks,
                  db: Session = Depends(get_db)):
    task = db.get(AnalysisTask, task_id)
    if not task:
        raise HTTPException(404, '任务不存在')

    # 源文件不在了就直接拒绝。若放行，worker 会先把上一次的结果全部删掉，
    # 再因为文件缺失失败 —— 用户等于白丢一份分析结果。
    if not task.files:
        raise HTTPException(409, '任务没有关联抓包文件')
    missing = [cf.filename for cf in task.files
               if not cf.stored_path or not os.path.isfile(cf.stored_path)]
    if missing:
        raise HTTPException(
            409, '源文件已不存在（可能被保留策略清理）：%s，请重新上传'
                 % '、'.join(missing))

    # 判定是否为"僵尸 analyzing"：状态是 analyzing 但本进程没有对应 worker
    # （典型场景：分析中途服务重启/崩溃，状态留在 analyzing 永远不动）
    with _run_lock:
        # 只要本进程还有该任务的 worker 在跑，就一律拒绝 ——
        # 不能只看 DB 状态：worker 启动后有一小段时间状态仍是 PENDING，
        # 此时再点一次会起第二个线程，两个线程同时删同一批结果。
        if task_id in _running:
            raise HTTPException(409, '任务正在分析中')

        stale = (task.status == TaskStatus.ANALYZING)

        running = sum(1 for v in _running.values() if v)
        if running >= settings.MAX_CONCURRENT_TASKS:
            raise HTTPException(429, '同时分析的任务过多（上限 %d）'
                                % settings.MAX_CONCURRENT_TASKS)
        # 占位必须与"检查"在同一把锁内完成，否则两个并发请求都能通过检查
        _running[task_id] = True

    try:
        if stale:
            # 清理僵尸状态，允许重新分析
            with session_scope() as s2:
                t2 = s2.get(AnalysisTask, task_id)
                if t2:
                    t2.error_message = '上次分析未正常结束（服务重启），已重置'
                    t2.progress = 0

        task.status = TaskStatus.PENDING
        task.progress = 0
        task.stage = '排队中'
        task.error_message = None
        db.commit()

        # 用线程而不是 BackgroundTasks：后者要等 HTTP 响应发出后才执行，
        # 大文件分析会拖住连接；独立线程可立即返回 task_id 供前端轮询
        threading.Thread(target=_worker, args=(task_id,), daemon=True).start()
    except BaseException:
        # 线程没起来就必须归还槽位，否则这个任务永远无法再次分析
        with _run_lock:
            _running.pop(task_id, None)
        raise

    db.refresh(task)
    return _task_brief(db, task)


def _worker(task_id: int):
    """后台分析线程 —— 不阻塞 HTTP 请求"""
    db = SessionLocal()
    try:
        analyzer.run_analysis(db, task_id)
    except Exception:
        pass          # 状态已由 run_analysis 写入
    finally:
        db.close()
        with _run_lock:
            _running.pop(task_id, None)


@router.post('/{task_id}/cancel', response_model=S.TaskBrief)
def cancel_task(task_id: int, db: Session = Depends(get_db)):
    """取消任务

    说明：后台线程无法安全强杀（可能正在调用 tshark），
    这里把状态置为 cancelled，worker 完成后不会覆盖。
    """
    task = db.get(AnalysisTask, task_id)
    if not task:
        raise HTTPException(404, '任务不存在')
    if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
        raise HTTPException(409, '任务已结束，无法取消')
    task.status = TaskStatus.CANCELLED
    task.stage = '已取消'
    db.commit()
    db.refresh(task)
    return _task_brief(db, task)


@router.delete('/{task_id}', status_code=204)
def delete_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(AnalysisTask, task_id)
    if not task:
        raise HTTPException(404, '任务不存在')
    # worker 正在跑时删除，会让它写回一堆已不存在的行（外键报错/脏状态）
    with _run_lock:
        if task_id in _running:
            raise HTTPException(409, '任务正在分析中，请先取消再删除')
    # 删除上传文件
    for cf in task.files:
        try:
            os.remove(cf.stored_path)
        except OSError:
            pass
    db.delete(task)
    db.commit()
    return None


# ---------------------------------------------------------------
# 概览（M10）
# ---------------------------------------------------------------
@router.get('/{task_id}/overview', response_model=S.Overview)
def get_overview(task_id: int, db: Session = Depends(get_db)):
    task = db.get(AnalysisTask, task_id)
    if not task:
        raise HTTPException(404, '任务不存在')

    sessions = db.scalars(
        select(BusinessSession).where(BusinessSession.task_id == task_id)
    ).all()
    streams = db.scalars(
        select(MediaStream).where(MediaStream.task_id == task_id)
    ).all()
    events = db.scalars(
        select(DiagnosticEvent).where(DiagnosticEvent.task_id == task_id)
    ).all()

    # 方法分布 / 响应码分布
    from ..models.entities import SipMessage
    msgs = db.scalars(
        select(SipMessage).where(SipMessage.task_id == task_id)
    ).all()
    method_dist = {}
    code_dist = {}
    for m in msgs:
        if m.method and m.is_request:
            method_dist[m.method] = method_dist.get(m.method, 0) + 1
        elif m.status_code:
            code_dist[str(m.status_code)] = code_dist.get(str(m.status_code), 0) + 1

    sev_dist = {}
    for e in events:
        sev_dist[e.severity] = sev_dist.get(e.severity, 0) + 1

    sig_dist = {}
    for s in sessions:
        sig_dist[s.signal_status] = sig_dist.get(s.signal_status, 0) + 1
    med_dist = {}
    for s in sessions:
        med_dist[s.media_status] = med_dist.get(s.media_status, 0) + 1

    return S.Overview(
        task_id=task.id,
        summary=task.summary or {},
        method_distribution=method_dist,
        code_distribution=code_dist,
        severity_distribution=sev_dist,
        signal_distribution=sig_dist,
        media_distribution=med_dist,
        session_types=_session_type_dist(sessions),
    )


def _session_type_dist(sessions) -> dict:
    d = {}
    for s in sessions:
        d[s.session_type] = d.get(s.session_type, 0) + 1
    return d

# ---------------------------------------------------------------
# 存储管理
# ---------------------------------------------------------------
@router.get('/storage/usage')
def storage_usage(db: Session = Depends(get_db)):
    """磁盘占用与保留策略"""
    from ..services import retention
    return {
        'usage': retention.total_disk_usage(),
        'policy': {
            'keep_tasks': settings.KEEP_TASKS,
            'keep_days': settings.KEEP_DAYS,
            'disk_budget_mb': settings.DISK_BUDGET_MB,
            'keep_uploads': settings.KEEP_UPLOADS,
        },
    }


@router.post('/storage/purge')
def storage_purge(keep: int | None = None, db: Session = Depends(get_db)):
    """手动清理：只保留最近 N 个任务的媒体文件

    keep 为空时按当前策略执行
    """
    from ..services import retention
    old = settings.KEEP_TASKS
    if keep is not None:
        settings.KEEP_TASKS = max(0, keep)
    try:
        r = retention.auto_purge(db)
    finally:
        if keep is not None:
            settings.KEEP_TASKS = old
    return r


@router.delete('/storage/all')
def storage_purge_all(db: Session = Depends(get_db)):
    """清空所有任务的媒体文件（保留数据库统计）"""
    from ..services import retention
    from sqlalchemy import select as _select
    tasks = db.scalars(_select(AnalysisTask)).all()
    total = {'removed': 0, 'freed_mb': 0, 'tasks': 0}
    for t in tasks:
        r = retention.purge_task_media(db, t.id, drop_task=False)
        if r['removed']:
            total['removed'] += r['removed']
            total['freed_mb'] = round(total['freed_mb'] + r['freed_mb'], 2)
            total['tasks'] += 1
    # SQLite 需要 VACUUM 才能真正回收磁盘
    total['vacuum'] = retention.vacuum_db(db)
    total['usage'] = retention.total_disk_usage()
    return total
