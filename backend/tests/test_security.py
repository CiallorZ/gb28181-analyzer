#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全加固回归：AI 网关校验 / 密钥文件权限 / 上传魔数 / Host 与 Origin 校验"""
from __future__ import annotations

import os
import stat
import sys
import urllib.request

import pytest

from app.core import security
from app.services import ai

PCAP = os.path.join(os.path.dirname(__file__), 'fixtures', 'sip-udp-basic.pcap')


# ---------------- validate_ai_base_url ----------------
@pytest.mark.parametrize('url', [
    'https://api.deepseek.com',
    'https://api.deepseek.com/',
    'https://API.DeepSeek.com/v1',
    'https://api.deepseek.com:443',
])
def test_official_host_allowed(url):
    assert security.validate_ai_base_url(url).startswith('https://')


@pytest.mark.parametrize('url', [
    'http://api.deepseek.com',                      # 明文
    'https://evil.example.com',                     # 任意主机（Key 外泄）
    'https://169.254.169.254/latest',               # 云元数据 SSRF
    'https://127.0.0.1:9000',                       # 回环
    'https://api.deepseek.com@evil.example.com',    # userinfo 伪装
    'https://user:pw@api.deepseek.com',             # 含凭据
    'https://api.deepseek.com/?x=1',                # 含查询参数
    'https://api.deepseek.com.evil.example.com',    # 后缀伪装
    'ftp://api.deepseek.com',
    'https://',
    '',
])
def test_unsafe_base_url_rejected(url):
    with pytest.raises(ValueError):
        security.validate_ai_base_url(url)


def test_allowlist_env_extends(monkeypatch):
    monkeypatch.setenv('AI_BASE_URL_ALLOWLIST', 'llm.corp.example, other.example')
    assert security.validate_ai_base_url('https://llm.corp.example/v1')
    with pytest.raises(ValueError):
        security.validate_ai_base_url('https://evil.example.com')


def test_insecure_http_requires_explicit_flag(monkeypatch):
    monkeypatch.setenv('AI_BASE_URL_ALLOWLIST', 'localhost')
    with pytest.raises(ValueError):
        security.validate_ai_base_url('http://localhost:11434')
    monkeypatch.setenv('AI_ALLOW_INSECURE_HTTP', '1')
    assert security.validate_ai_base_url('http://localhost:11434')


# ---------------- /ai/config ----------------
def test_set_config_rejects_evil_base_url(client):
    r = client.post('/api/v1/ai/config', json={'base_url': 'https://evil.example.com'})
    assert r.status_code == 400
    assert 'AI_BASE_URL_ALLOWLIST' in r.json()['error']


def test_set_config_accepts_official_and_resets_empty(client):
    r = client.post('/api/v1/ai/config', json={'base_url': 'https://api.deepseek.com/'})
    assert r.status_code == 200
    assert r.json()['base_url'] == 'https://api.deepseek.com'
    r = client.post('/api/v1/ai/config', json={'base_url': '  '})
    assert r.status_code == 200
    assert r.json()['base_url'] == ai.DEFAULT_BASE


def test_post_refuses_legacy_unsafe_config(monkeypatch):
    """旧版本写入的不安全 base_url：发送前必须拒绝，而不是把 Key 发出去"""
    monkeypatch.setattr(ai, 'load_config', lambda: {
        'api_key': 'sk-test-1234567890', 'base_url': 'https://evil.example.com'})

    def boom(*a, **k):                       # 若走到网络层说明校验被绕过
        raise AssertionError('不应发起网络请求')
    monkeypatch.setattr(urllib.request.OpenerDirector, 'open', boom)
    with pytest.raises(RuntimeError, match='不安全'):
        ai._post({'model': 'x', 'messages': []})


def test_redirects_are_not_followed():
    h = ai._NoRedirect()
    req = urllib.request.Request('https://api.deepseek.com/x')
    assert h.redirect_request(req, None, 302, 'Found', {}, 'https://evil.example.com') is None


# ---------------- 密钥文件 ----------------
@pytest.mark.skipif(sys.platform.startswith('win'), reason='POSIX 权限位')
def test_config_file_mode_0600(tmp_path, monkeypatch):
    monkeypatch.setattr(ai, 'CONFIG_PATH', tmp_path / 'ai_config.json')
    ai.save_config({'api_key': 'sk-secret'})
    assert stat.S_IMODE(os.stat(ai.CONFIG_PATH).st_mode) == 0o600
    ai.save_config({'api_key': 'sk-secret-2'})        # 覆盖写入同样 0600
    assert stat.S_IMODE(os.stat(ai.CONFIG_PATH).st_mode) == 0o600


def test_env_key_takes_precedence_and_is_masked(monkeypatch):
    monkeypatch.setattr(ai, 'load_config', lambda: {'api_key': 'sk-from-file-aaaa'})
    monkeypatch.setenv('DEEPSEEK_API_KEY', 'sk-from-env-bbbbbb')
    pub = ai.public_config()
    assert pub['has_key'] is True and pub['key_hint'].endswith('bbbb')
    assert 'api_key' not in pub


# ---------------- 上传魔数 ----------------
def test_upload_rejects_non_capture_content(client):
    r = client.post('/api/v1/tasks/upload',
                    files={'file': ('fake.pcap', b'MZ\x90\x00 not a capture' * 50)})
    assert r.status_code == 400
    assert '魔数' in r.json()['error']
    from app.core.config import settings
    leftovers = [f for f in os.listdir(settings.UPLOAD_DIR) if f.endswith('fake.pcap')]
    assert leftovers == []                      # 被拒绝的文件不应遗留在磁盘


@pytest.mark.parametrize('magic', security.PCAP_MAGICS)
def test_looks_like_capture_accepts_all_magics(magic):
    assert security.looks_like_capture(magic + b'\x00' * 20)


def test_upload_accepts_real_pcap(client):
    with open(PCAP, 'rb') as f:
        r = client.post('/api/v1/tasks/upload', files={'file': ('ok.pcap', f.read())})
    assert r.status_code == 201


# ---------------- Host / Origin ----------------
def test_untrusted_host_rejected(client):
    r = client.get('/api/v1/health', headers={'Host': 'attacker.example.com'})
    assert r.status_code == 400


def test_cross_site_post_rejected(client):
    r = client.post('/api/v1/tasks/storage/purge?keep=1000', headers={'Origin': 'https://attacker.example.com'})
    assert r.status_code == 403
    assert '跨站' in r.json()['error']


def test_same_origin_and_cors_origin_post_allowed(client):
    for origin in ('http://testserver', 'http://localhost:5173'):
        r = client.post('/api/v1/tasks/storage/purge?keep=1000', headers={'Origin': origin})
        assert r.status_code == 200, origin


def test_forwarded_host_counts_as_same_origin(client):
    r = client.post('/api/v1/tasks/storage/purge?keep=1000', headers={
        'Origin': 'https://analyzer.example.com',
        'X-Forwarded-Host': 'analyzer.example.com',
        'X-Forwarded-Proto': 'https'})
    assert r.status_code == 200


def test_get_requests_ignore_origin(client):
    r = client.get('/api/v1/health', headers={'Origin': 'https://attacker.example.com'})
    assert r.status_code == 200


def test_default_allowed_hosts_by_bind():
    assert security.default_allowed_hosts('127.0.0.1')[0] == 'localhost'
    assert security.default_allowed_hosts('0.0.0.0') == ['*']
