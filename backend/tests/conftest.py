#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pytest 公共装置

关键约束：`app.core.config` 在 import 时就把 DATABASE_URL / DATA_DIR 固化了，
所以必须在导入任何 app 模块**之前**改写环境变量，否则测试会写到真实数据库。
本文件由 pytest 最先加载，正好满足这个顺序要求。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

# ---- 隔离运行环境（必须在 import app 之前）----
_TMP = Path(tempfile.mkdtemp(prefix='gba-test-'))
os.environ['DATA_DIR'] = str(_TMP)
os.environ['DATABASE_URL'] = 'sqlite:///' + (_TMP / 'test.db').as_posix()
os.environ['KEEP_TASKS'] = '50'         # 测试里不做保留策略清理，避免删掉样本
os.environ['KEEP_DAYS'] = '0'
os.environ['DISK_BUDGET_MB'] = '100000'
os.environ['MAX_CONCURRENT_TASKS'] = '2'
os.environ['KEEP_UPLOADS'] = '1'
os.environ['ALLOWED_HOSTS'] = 'testserver,localhost,127.0.0.1'   # TestClient 的 Host 为 testserver
os.environ.pop('AI_BASE_URL_ALLOWLIST', None)
os.environ.pop('AI_ALLOW_INSECURE_HTTP', None)
os.environ.pop('DEEPSEEK_API_KEY', None)

FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def pytest_sessionfinish(session, exitstatus):      # noqa: ARG001
    shutil.rmtree(_TMP, ignore_errors=True)


@pytest.fixture(scope='session', autouse=True)
def _init_db():
    """建表。client fixture 会走 startup 建表，但纯 service 层用例
    （不启动 FastAPI）也需要表存在，所以这里统一建一次。"""
    from app.core.db import init_db
    init_db()
    yield


@pytest.fixture(scope='session')
def client():
    """FastAPI 测试客户端（会触发 startup：建表 + 清理僵尸任务）"""
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db():
    from app.core.db import SessionLocal
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture(autouse=True)
def _clean_state():
    """每个用例前后清空任务表与并发槽位，避免用例互相污染"""
    from sqlalchemy import delete

    from app.api import tasks as tasks_api
    from app.core.db import SessionLocal
    from app.models.entities import (
        AnalysisTask, BusinessSession, CaptureFile, Device, DiagnosticEvent,
        Endpoint, MediaMetric, MediaStream, PacketIndex, SipDialog, SipMessage,
    )

    def _wipe():
        s = SessionLocal()
        try:
            # 子表在前，父表在后（SQLite 开了 foreign_keys=ON）
            s.execute(delete(MediaMetric))
            for model in (MediaStream, SipDialog, SipMessage, DiagnosticEvent,
                          BusinessSession, Device, Endpoint, PacketIndex,
                          CaptureFile):
                s.execute(delete(model))
            s.execute(delete(AnalysisTask))
            s.commit()
        finally:
            s.close()

    _wipe()
    with tasks_api._run_lock:
        tasks_api._running.clear()
    yield
    with tasks_api._run_lock:
        tasks_api._running.clear()
    _wipe()


@pytest.fixture()
def make_task(db):
    """创建一个带抓包文件的任务；path 为 None 时指向不存在的文件"""
    from app.models.entities import AnalysisTask, CaptureFile, TaskStatus

    def _make(name='样本', path=None, status=TaskStatus.PENDING):
        p = Path(path) if path else (_TMP / ('missing_%s.pcap' % name))
        task = AnalysisTask(name=name, status=status, configuration={})
        db.add(task)
        db.flush()
        db.add(CaptureFile(task_id=task.id, filename=p.name,
                           stored_path=str(p), file_size=0))
        db.commit()
        db.refresh(task)
        return task

    return _make
