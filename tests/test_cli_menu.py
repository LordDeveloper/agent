import sys

from agent import __version__
from agent.cli import build_parser, main
from agent.tui import LOGO, LOGO_ASCII, TAGLINE, decode_key


def test_logo_and_tagline():
    assert "█" in LOGO
    assert LOGO.count("\n") >= 5
    assert LOGO_ASCII.count("\n") >= 4
    assert "Netinja" in TAGLINE
    assert __version__ == "0.3.23"


def test_decode_key_arrows_and_enter():
    assert decode_key("\x1b[A") == "up"
    assert decode_key("\x1b[B") == "down"
    assert decode_key("\x1b[C") == "right"
    assert decode_key("\x1b[D") == "left"
    assert decode_key("\r") == "enter"
    assert decode_key("\n") == "enter"
    assert decode_key("\x1b") == "esc"
    assert decode_key(" ") == "space"
    assert decode_key("1") == "1"


def test_parser_has_nested_menu_command():
    parser = build_parser()
    args = parser.parse_args(["menu"])
    assert args.command == "menu"
    assert callable(args.func)


def test_main_without_args_on_non_tty_prints_help(capsys, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "serve" in out
    assert "menu" in out


def test_menu_command_requires_tty(capsys, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert main(["menu"]) == 2
    err = capsys.readouterr().err
    assert "TTY" in err
