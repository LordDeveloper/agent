from agent.support import normalize_xray_client, xray_protocol_user, xray_users_settings


def test_xray_protocol_user_omits_blank_shadowsocks_method():
    user = xray_protocol_user('shadowsocks', {
        'email': 'a@b.c',
        'password': 'secret',
        'method': '   ',
        'extra': {'method': ''},
    })
    assert 'method' not in user
    assert user['password'] == 'secret'


def test_normalize_xray_client_drops_blank_method():
    client = normalize_xray_client({
        'email': 'a@b.c',
        'method': '',
        'extra': {'method': '   ', 'keep': 'x'},
    })
    assert 'method' not in client
    assert client['extra'] == {'keep': 'x'}


def test_xray_users_settings_strips_blank_inbound_method():
    settings = xray_users_settings(
        'shadowsocks',
        {'method': '', 'password': '', 'network': 'tcp,udp'},
        [{'email': 'a@b.c', 'password': 'secret', 'method': 'chacha20-ietf-poly1305'}],
    )
    assert 'method' not in settings
    assert settings['clients'][0]['method'] == 'chacha20-ietf-poly1305'
