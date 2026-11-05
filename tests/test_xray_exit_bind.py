from agent.support.xray_exit_bind import script_lines


def test_script_lines_install_the_interface_table_not_main():
    lines = script_lines(["wg-fi"])
    rendered = "\n".join(lines)
    assert 'dev "wg-fi"' in rendered
    assert "table main" not in rendered
    route_lines = [line for line in lines if "ip route replace" in line]
    assert route_lines
    for line in route_lines:
        assert " table " in line
        table = line.rsplit(" table ", 1)[1].split()[0]
        assert int(table) >= 10000
