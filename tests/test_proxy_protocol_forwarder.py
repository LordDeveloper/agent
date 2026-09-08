from agent.support.proxy_protocol_forwarder import (
    ForwardRule,
    inbound_accepts_proxy_protocol,
    rules_from_inbounds,
)


def test_inbound_accepts_proxy_protocol_on_ws_settings():
    inbound = {
        "port": 2054,
        "streamSettings": {
            "network": "ws",
            "wsSettings": {"acceptProxyProtocol": True, "path": "/ws"},
        },
    }
    assert inbound_accepts_proxy_protocol(inbound) is True


def test_inbound_accepts_proxy_protocol_false_without_flag():
    inbound = {
        "port": 443,
        "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}},
    }
    assert inbound_accepts_proxy_protocol(inbound) is False


def test_rules_from_inbounds_listen_on_port_minus_one():
    inbounds = [
        {
            "tag": "inbound-7",
            "listen": "0.0.0.0",
            "port": 2054,
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"acceptProxyProtocol": True, "path": "/abc"},
            },
        }
    ]

    rules = rules_from_inbounds(inbounds)
    assert rules == [
        ForwardRule(listen="0.0.0.0:2053", target="127.0.0.1:2054", tag="inbound-7")
    ]


def test_rules_from_inbounds_skip_without_proxy_protocol():
    inbounds = [
        {
            "tag": "inbound-1",
            "listen": "0.0.0.0",
            "port": 443,
            "streamSettings": {"network": "tcp", "security": "reality"},
        }
    ]
    assert rules_from_inbounds(inbounds) == []


def test_rules_from_inbounds_deduplicate_listen_port():
    inbounds = [
        {
            "tag": "inbound-1",
            "listen": "0.0.0.0",
            "port": 1002,
            "streamSettings": {"tcpSettings": {"acceptProxyProtocol": True}},
        },
        {
            "tag": "inbound-2",
            "listen": "0.0.0.0",
            "port": 1002,
            "streamSettings": {"tcpSettings": {"acceptProxyProtocol": True}},
        },
    ]

    rules = rules_from_inbounds(inbounds)
    assert len(rules) == 1
    assert rules[0].tag == "inbound-1"
