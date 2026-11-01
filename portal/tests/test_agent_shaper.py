"""Removing device caps must preserve manually configured shared/gaming pipes."""
import pytest

import fw_agent


def test_clear_limit_only_deletes_pipes_removed_by_tagged_helper(monkeypatch):
    calls = []
    def shaper(*args):
        assert args == ('clear', 'portal-00:11:22:33:44:55')
        return {'ok': True, 'removed_pipes': [10000, 10001]}
    def run(cmd, **kwargs):
        calls.append(cmd)
        # The old global sweep would discover and wrongly delete the manual 20000 pipe.
        return 0, '10000: pipe\n10001: pipe\n10002: another device\n20000: manual FQ_CODEL\n', ''
    monkeypatch.setattr(fw_agent, '_shaper', shaper)
    monkeypatch.setattr(fw_agent, 'run', run)
    fw_agent._clear_limit('00:11:22:33:44:55')
    assert calls == [['dnctl', 'pipe', '10000', 'delete'], ['dnctl', 'pipe', '10001', 'delete']]


def test_clear_limit_without_ownership_report_never_sweeps_kernel(monkeypatch):
    monkeypatch.setattr(fw_agent, '_shaper', lambda *args: {'ok': True, 'removed': 0})
    monkeypatch.setattr(fw_agent, 'run', lambda *args, **kw: pytest.fail('unowned pipe deletion'))
    fw_agent._clear_limit('00:11:22:33:44:55')


def test_failed_clear_does_not_delete_kernel_pipes(monkeypatch):
    def failure(*args):
        raise fw_agent.ActionFailed('model clear failed')
    monkeypatch.setattr(fw_agent, '_shaper', failure)
    monkeypatch.setattr(fw_agent, 'run', lambda *args, **kw: pytest.fail('pipe deleted after failed clear'))
    with pytest.raises(fw_agent.ActionFailed):
        fw_agent._clear_limit('00:11:22:33:44:55')
