from agent.support.xray_console import merge_routing_rules


def test_merge_routing_rules_replaces_users_and_keeps_inbounds():
    config = {
        "inbounds": [{"tag": "inbound-1644", "settings": {"clients": [{"email": "s0NTPq"}]}}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"tag": "route-node:12", "ruleTag": "route-node:12"}],
        },
    }
    rules = [{
        "tag": "route-node:12",
        "user": ["s0NTPq"],
        "outboundTag": "mullvad-se",
    }]

    updated = merge_routing_rules(config, rules, {"domainMatcher": "hybrid"})

    assert updated["inbounds"] == config["inbounds"]
    assert updated["routing"]["domainStrategy"] == "AsIs"
    assert updated["routing"]["domainMatcher"] == "hybrid"
    assert updated["routing"]["rules"] == rules
    assert config["routing"]["rules"][0]["tag"] == "route-node:12"
