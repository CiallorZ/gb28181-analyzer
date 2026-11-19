#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行配置（环境变量优先，便于 Docker/本地切换）"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent   # backend/
PROJECT_DIR = BASE_DIR.parent                              # 仓库根目录


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


class Settings:
    # 服务
    HOST: str = _env('HOST', '127.0.0.1')
    PORT: int = int(_env('PORT', '8788'))
    DEBUG: bool = _env('DEBUG', '1') == '1'

    # 数据库：默认 SQLite，便于开箱即用；schema 与 PostgreSQL 兼容
    # 切 PG 时设 DATABASE_URL=postgresql+psycopg://user:pass@host/db
    DATABASE_URL: str = _env(
        'DATABASE_URL',
        'sqlite:///' + str((PROJECT_DIR / 'data' / 'analyzer.db').as_posix()),
    )

    # 存储
    DATA_DIR: Path = Path(_env('DATA_DIR', str(PROJECT_DIR / 'data')))
    UPLOAD_DIR: Path = DATA_DIR / 'uploads'
    REBUILD_DIR: Path = DATA_DIR / 'rebuilt'
    REPORT_DIR: Path = DATA_DIR / 'reports'

    # 上传限制
    MAX_UPLOAD_MB: int = int(_env('MAX_UPLOAD_MB', '2048'))
    ALLOWED_EXT = ('.pcap', '.pcapng', '.cap')

    # 并发
    MAX_CONCURRENT_TASKS: int = int(_env('MAX_CONCURRENT_TASKS', '2'))

    # ---- 任务保留策略 ----
    # KEEP_TASKS=0 表示不保留历史：分析完成后立即清理原文件与重建产物
    # KEEP_TASKS=N 表示只保留最近 N 个任务
    KEEP_TASKS: int = int(_env('KEEP_TASKS', '5'))
    # 任务最大保留天数（0=不按时间清理）
    KEEP_DAYS: int = int(_env('KEEP_DAYS', '7'))
    # 磁盘占用上限（MB），超过则按最旧优先清理
    DISK_BUDGET_MB: int = int(_env('DISK_BUDGET_MB', '2048'))
    # 是否保留上传的原始 pcap（关掉可省大量空间，但不能重新分析）
    KEEP_UPLOADS: bool = _env('KEEP_UPLOADS', '1') == '1'

    # 外部工具
    TSHARK_PATH: str = _env('TSHARK_PATH', '')
    FFMPEG_PATH: str = _env('FFMPEG_PATH', '')

    # Host 头白名单（逗号分隔，'*' 表示不限制）。
    # 默认：仅监听本机时只接受本机 Host；对外监听(HOST=0.0.0.0)时不限制，
    # 暴露到网络前请显式设置，例如 ALLOWED_HOSTS=analyzer.example.com
    ALLOWED_HOSTS: list = [
        h.strip() for h in os.environ['ALLOWED_HOSTS'].split(',') if h.strip()
    ] if os.environ.get('ALLOWED_HOSTS') else None   # None=按 HOST 取默认

    # CORS（前端 dev server）
    CORS_ORIGINS: list = _env(
        'CORS_ORIGINS',
        'http://localhost:5173,http://127.0.0.1:5173'
    ).split(',')


settings = Settings()
if settings.ALLOWED_HOSTS is None:
    from .security import default_allowed_hosts
    settings.ALLOWED_HOSTS = default_allowed_hosts(settings.HOST)

for d in (settings.DATA_DIR, settings.UPLOAD_DIR,
          settings.REBUILD_DIR, settings.REPORT_DIR):
    d.mkdir(parents=True, exist_ok=True)
