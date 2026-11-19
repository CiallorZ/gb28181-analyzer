#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全辅助：AI 网关地址校验、抓包文件头校验、Host/Origin 判定

背景：本服务默认无账号体系（本地单用户工具），因此必须保证
  1. API Key 不会被配置接口改写的 base_url 带到任意主机；
  2. 浏览器跨站请求（CSRF / DNS rebinding）无法驱动状态变更接口；
  3. 上传的不是抓包文件时尽早拒绝，而不是落盘后才在分析阶段失败。
"""
from __future__ import annotations

import os
from urllib.parse import urlsplit

# ---------------------------------------------------------------
# AI 网关（base_url）
# ---------------------------------------------------------------
# 默认只允许官方域名。API Key 会随请求发往 base_url 指向的主机，
# 所以改成"任意主机"等同于把 Key 交给对方。
DEFAULT_AI_HOSTS = ('api.deepseek.com',)


def _csv_env(key: str) -> list[str]:
    return [x.strip().lower() for x in os.environ.get(key, '').split(',')
            if x.strip()]


def ai_allowed_hosts() -> set[str]:
    """允许的 AI 网关主机 = 官方域名 + 环境变量 AI_BASE_URL_ALLOWLIST"""
    return set(DEFAULT_AI_HOSTS) | set(_csv_env('AI_BASE_URL_ALLOWLIST'))


def validate_ai_base_url(url: str) -> str:
    """校验并规范化 AI 网关地址；不合法抛 ValueError（消息可直接展示给用户）"""
    raw = (url or '').strip()
    if not raw:
        raise ValueError('网关地址不能为空')
    parts = urlsplit(raw)
    allow_http = os.environ.get('AI_ALLOW_INSECURE_HTTP', '0') == '1'
    if parts.scheme not in (('https', 'http') if allow_http else ('https',)):
        raise ValueError('网关地址必须以 https:// 开头')
    if parts.username or parts.password:
        raise ValueError('网关地址不能包含用户名或密码')
    if parts.query or parts.fragment:
        raise ValueError('网关地址不能包含查询参数或锚点')
    host = (parts.hostname or '').lower()
    if not host:
        raise ValueError('网关地址缺少主机名')
    try:
        parts.port            # 触发端口合法性检查
    except ValueError:
        raise ValueError('网关地址端口无效')
    if host not in ai_allowed_hosts():
        raise ValueError(
            '网关主机 %s 不在允许列表内。API Key 会发往该主机，默认只允许 %s；'
            '如需使用其他 OpenAI 兼容网关，请在服务端设置环境变量 '
            'AI_BASE_URL_ALLOWLIST=%s 后重启'
            % (host, '、'.join(DEFAULT_AI_HOSTS), host))
    return raw.rstrip('/')


# ---------------------------------------------------------------
# 抓包文件头
# ---------------------------------------------------------------
PCAP_MAGICS = (
    b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',   # pcap（微秒，小端/大端）
    b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d',   # pcap（纳秒，小端/大端）
    b'\x0a\x0d\x0d\x0a',                        # pcapng
)


def looks_like_capture(head: bytes) -> bool:
    return head[:4] in PCAP_MAGICS


# ---------------------------------------------------------------
# Host / Origin
# ---------------------------------------------------------------
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost', '::1', '[::1]')


def is_loopback(host: str) -> bool:
    return (host or '').strip().lower() in LOOPBACK_HOSTS


def default_allowed_hosts(bind_host: str) -> list[str]:
    """仅监听本机时，默认只接受本机 Host 头（防 DNS rebinding）；
    对外监听说明运维者主动暴露服务，默认不限制，需自行设置 ALLOWED_HOSTS。"""
    if is_loopback(bind_host):
        return ['localhost', '127.0.0.1', '[::1]', '::1']
    return ['*']


def origin_allowed(origin: str, host_candidates: list[str],
                   proto_candidates: list[str],
                   cors_origins: list[str]) -> bool:
    """同源或在 CORS 白名单内才允许状态变更请求"""
    o = (origin or '').strip().rstrip('/').lower()
    if not o:
        return True
    if o in {c.strip().rstrip('/').lower() for c in cors_origins}:
        return True
    for p in proto_candidates:
        for h in host_candidates:
            if h and o == '%s://%s' % (p.lower(), h.lower()):
                return True
    return False
