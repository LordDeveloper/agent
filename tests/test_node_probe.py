from agent.support.node_probe import probe_exit_interface, probe_outbound_tag, probe_region_node


def test_probe_outbound_missing_tag():
    result = probe_outbound_tag('missing', [{'tag': 'direct', 'protocol': 'freedom'}])
    assert result['ok'] is False


def test_probe_region_node_requires_path():
    result = probe_region_node(node_id=1, outbound_tag=None, exit_interface=None, outbounds=[])
    assert result['ok'] is False


def test_probe_exit_interface_missing():
    result = probe_exit_interface('eth999')
    assert result['ok'] is False
