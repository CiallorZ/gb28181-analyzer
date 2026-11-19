#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DeepSeek AI 分析接口（SSE 流式）"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import validate_ai_base_url
from ..models.entities import AnalysisTask
from ..services import ai

router = APIRouter(prefix='/ai', tags=['ai'])


class ConfigIn(BaseModel):
    api_key: str | None = None
    model: str | None = None
    base_url: str | None = None


class ChatIn(BaseModel):
    question: str
    history: list = []


def _sse(event: str, data: dict) -> str:
    return 'event: %s\ndata: %s\n\n' % (
        event, json.dumps(data, ensure_ascii=False))


@router.get('/config')
def get_config():
    return ai.public_config()


@router.post('/config')
def set_config(body: ConfigIn):
    cfg = ai.load_config()
    if body.api_key is not None and body.api_key.strip():
        cfg['api_key'] = body.api_key.strip()
    if body.model is not None:
        cfg['model'] = body.model.strip() or ai.DEFAULT_MODEL
    if body.base_url is not None:
        try:
            cfg['base_url'] = (validate_ai_base_url(body.base_url)
                               if body.base_url.strip() else ai.DEFAULT_BASE)
        except ValueError as e:
            raise HTTPException(400, str(e))
    ai.save_config(cfg)
    return ai.public_config()


@router.post('/test')
def test_conn():
    try:
        out = ai.test_connection()
        return {'ok': True, 'reply': out[:80]}
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@router.post('/analyze/{task_id}')
def analyze_stream(task_id: int, db: Session = Depends(get_db)):
    """真正的逐 token 流式（SSE）"""
    task = db.get(AnalysisTask, task_id)
    if not task:
        raise HTTPException(404, '任务不存在')
    if task.status != 'completed':
        raise HTTPException(400, '任务尚未完成分析')

    def gen():
        # 用一个队列在同步回调与生成器之间传递增量
        import queue
        import threading

        q: queue.Queue = queue.Queue()
        result = {'text': '', 'error': None}

        def worker():
            try:
                def on_delta(t):
                    q.put(('delta', t))
                text = ai.analyze(db, task_id, on_delta=on_delta)
                result['text'] = text
                q.put(('done', text))
            except RuntimeError as e:
                q.put(('error', str(e)))
            except Exception as e:
                q.put(('error', '分析失败：%s' % e))

        th = threading.Thread(target=worker, daemon=True)
        th.start()

        while True:
            try:
                kind, payload = q.get(timeout=180)
            except queue.Empty:
                yield _sse('error', {'error': '分析超时'})
                break
            if kind == 'delta':
                yield _sse('delta', {'t': payload})
            elif kind == 'done':
                yield _sse('done', {'text': payload})
                break
            elif kind == 'error':
                yield _sse('error', {'error': payload})
                break

    return StreamingResponse(gen(), media_type='text/event-stream',
                             headers={'Cache-Control': 'no-cache',
                                      'X-Accel-Buffering': 'no'})


@router.post('/chat/{task_id}')
def chat(task_id: int, body: ChatIn, db: Session = Depends(get_db)):
    task = db.get(AnalysisTask, task_id)
    if not task:
        raise HTTPException(404, '任务不存在')
    if task.status != 'completed':
        raise HTTPException(400, '任务尚未完成分析')

    def gen():
        import queue
        import threading

        q: queue.Queue = queue.Queue()

        def worker():
            try:
                def on_delta(t):
                    q.put(('delta', t))
                text = ai.chat(db, task_id, body.history, body.question,
                               on_delta=on_delta)
                q.put(('done', text))
            except RuntimeError as e:
                q.put(('error', str(e)))
            except Exception as e:
                q.put(('error', '对话失败：%s' % e))

        th = threading.Thread(target=worker, daemon=True)
        th.start()

        while True:
            try:
                kind, payload = q.get(timeout=180)
            except queue.Empty:
                yield _sse('error', {'error': '对话超时'})
                break
            if kind == 'delta':
                yield _sse('delta', {'t': payload})
            elif kind == 'done':
                yield _sse('done', {'text': payload})
                break
            elif kind == 'error':
                yield _sse('error', {'error': payload})
                break

    return StreamingResponse(gen(), media_type='text/event-stream',
                             headers={'Cache-Control': 'no-cache',
                                      'X-Accel-Buffering': 'no'})
