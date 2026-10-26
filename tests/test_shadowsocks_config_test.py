from agent.support.config_validate import prepare_shadowsocks_for_config_test


def test_aead_without_client_list_stays_multi_user():
    settings = {"network": "tcp,udp"}

    prepare_shadowsocks_for_config_test(settings)

    assert settings["clients"] == []
    assert "password" not in settings


def test_existing_client_list_is_left_alone():
    settings = {
        "network": "tcp,udp",
        "clients": [{"password": "secret", "method": "aes-128-gcm", "email": "a@x"}],
    }

    prepare_shadowsocks_for_config_test(settings)

    assert settings["clients"][0]["password"] == "secret"


def test_single_user_password_is_left_alone():
    settings = {"method": "chacha20-ietf-poly1305", "password": "secret", "network": "tcp,udp"}

    prepare_shadowsocks_for_config_test(settings)

    assert "clients" not in settings
    assert settings["password"] == "secret"


def test_shadowsocks_2022_without_users_is_left_alone():
    settings = {
        "method": "2022-blake3-aes-128-gcm",
        "password": "cGFzc3dvcmQxMjM0NTY3OA==",
        "network": "tcp,udp",
    }

    prepare_shadowsocks_for_config_test(settings)

    assert "clients" not in settings
