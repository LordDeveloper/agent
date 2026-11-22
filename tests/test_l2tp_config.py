from agent.support.l2tp_config import (
    render_ipsec_conf,
    render_xl2tpd_conf,
    sanitize_listen_addr,
)


def test_blank_listen_addr_keeps_every_interface():
    conf = render_xl2tpd_conf([{'subnet': '10.164.0.0/16'}], templates={})
    assert 'listen-addr' not in conf
    assert 'port = 1701\n' in conf
    ipsec = render_ipsec_conf([], templates={})
    assert '    left=%any\n' in ipsec


def test_listen_addr_is_written_to_xl2tpd_and_ipsec():
    templates = {'listen_addr': ' 203.0.113.10 '}
    conf = render_xl2tpd_conf([{'subnet': '10.164.0.0/16'}], templates=templates)
    assert 'listen-addr = 203.0.113.10\n' in conf
    assert conf.index('port = 1701') < conf.index('listen-addr = 203.0.113.10')
    assert conf.index('listen-addr = 203.0.113.10') < conf.index('auth file =')
    ipsec = render_ipsec_conf([], templates=templates)
    assert '    left=203.0.113.10\n' in ipsec


def test_sanitize_listen_addr():
    assert sanitize_listen_addr(' 203.0.113.10 ') == '203.0.113.10'
    assert sanitize_listen_addr('[2001:db8::10]') == '2001:db8::10'
    assert sanitize_listen_addr('0.0.0.0') == ''
    assert sanitize_listen_addr('::') == ''
    assert sanitize_listen_addr('%any') == ''
    assert sanitize_listen_addr('vpn.example.com') == ''
    assert sanitize_listen_addr('999.1.1.1') == ''
