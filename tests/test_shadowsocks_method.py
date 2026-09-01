from agent.support import (
    normalize_xray_client,
    repair_shadowsocks_settings,
    xray_protocol_user,
    xray_users_settings,
)


def test_xray_protocol_user_omits_blank_shadowsocks_method():
    user = xray_protocol_user('shadowsocks', {
        'email': 'a@b.c',
        'password': 'secret',
        'method': '   ',
        'extra': {'method': ''},
    })
    assert user['method'] == 'chacha20-ietf-poly1305'
    assert user['password'] == 'secret'


def test_normalize_xray_client_drops_blank_method():
    client = normalize_xray_client({
        'email': 'a@b.c',
        'method': '',
        'extra': {'method': '   ', 'keep': 'x'},
    })
    assert 'method' not in client
    assert client['extra'] == {'keep': 'x'}


def test_xray_protocol_user_defaults_aead_method_when_missing():
    user = xray_protocol_user('shadowsocks', {
        'email': 'a@b.c',
        'password': 'secret',
    })
    assert user['method'] == 'chacha20-ietf-poly1305'


def test_xray_protocol_user_does_not_default_method_for_ss2022_inbound():
    user = xray_protocol_user(
        'shadowsocks',
        {'email': 'a@b.c', 'password': 'user-psk'},
        inbound_settings={'method': '2022-blake3-aes-128-gcm', 'password': 'server-psk'},
    )
    assert 'method' not in user
    assert user['password'] == 'user-psk'


def test_repair_shadowsocks_settings_backfills_blank_client_cipher():
    settings = {
        'method': '',
        'password': '',
        'network': 'tcp,udp',
        'clients': [
            {'email': 'a@b.c', 'password': 'secret', 'method': ''},
            {'email': 'b@b.c', 'password': 'secret2'},
        ],
    }
    assert repair_shadowsocks_settings(settings) is True
    assert 'method' not in settings
    assert settings['clients'][0]['method'] == 'chacha20-ietf-poly1305'
    assert settings['clients'][1]['method'] == 'chacha20-ietf-poly1305'


def test_xray_users_settings_strips_blank_inbound_method():
    settings = xray_users_settings(
        'shadowsocks',
        {'method': '', 'password': '', 'network': 'tcp,udp'},
        [{'email': 'a@b.c', 'password': 'secret', 'method': 'chacha20-ietf-poly1305'}],
    )
    assert 'method' not in settings
    assert settings['clients'][0]['method'] == 'chacha20-ietf-poly1305'
