from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Iterable


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
REVERSE = "\033[7m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BLUE = "\033[94m"

WIDTH = 58

LOGO = r"""
 █████╗  ██████╗ ███████╗███╗   ██╗████████╗
██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝
""".strip("\n")

LOGO_ASCII = r"""
   _    ____ _____ _   _ _____
  / \  / ___| ____| \ | |_   _|
 / _ \| |  _|  _| |  \| | | |
/ ___ \ |_| | |___| |\  | | |
/_/   \_\____|_____|_| \_| |_|
""".strip("\n")

TAGLINE = "VPN node agent for Netinja"


@dataclass(frozen=True)
class Choice:
    value: str
    label: str
    color: str = WHITE
    shortcut: str | None = None


def enable_ansi() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def is_interactive() -> bool:
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def paint(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def logo() -> str:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    if encoding.startswith("utf"):
        return LOGO
    return LOGO_ASCII


def double_line() -> str:
    return paint("═" * WIDTH, YELLOW)


def single_line() -> str:
    return paint("─" * WIDTH, WHITE)


def hide_cursor() -> None:
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()


def show_cursor() -> None:
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def clear_screen() -> None:
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def kv(label: str, value: str, value_color: str = GREEN) -> str:
    padded = f"{label + ':':<16}"
    return f"  {paint(padded, WHITE)}  {paint(value, value_color)}"


def decode_key(seq: str) -> str:
    """Map a raw terminal sequence to a logical key name."""
    if not seq:
        return ""
    if seq in {"\r", "\n"}:
        return "enter"
    if seq in {"\x03"}:
        return "ctrl-c"
    if seq in {"\x1b"}:
        return "esc"
    if seq in {"\x1b[A", "\x1bOA", "\x00H", "\xe0H"}:
        return "up"
    if seq in {"\x1b[B", "\x1bOB", "\x00P", "\xe0P"}:
        return "down"
    if seq in {"\x1b[C", "\x1bOC", "\x00M", "\xe0M"}:
        return "right"
    if seq in {"\x1b[D", "\x1bOD", "\x00K", "\xe0K"}:
        return "left"
    if seq in {" ", "\x20"}:
        return "space"
    return seq


def read_key() -> str:
    if os.name == "nt":
        import msvcrt

        ch = msvcrt.getwch()
        if ch in {"\x00", "\xe0"}:
            return decode_key(ch + msvcrt.getwch())
        return decode_key(ch)

    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            extra = sys.stdin.read(1)
            if extra in {"[", "O"}:
                extra += sys.stdin.read(1)
            return decode_key(ch + extra)
        return decode_key(ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def pause(message: str = "Press Enter to continue...") -> None:
    show_cursor()
    try:
        input(paint(f"\n  {message}", DIM))
    except EOFError:
        pass


def prompt_text(label: str, default: str = "") -> str:
    show_cursor()
    suffix = f" [{default}]" if default else ""
    try:
        value = input(paint(f"  {label}{suffix}: ", CYAN)).strip()
    except EOFError:
        value = ""
    return value or default


def select(choices: Iterable[Choice], *, pointer: str = "❯") -> str | None:
    rows = list(choices)
    if not rows:
        return None
    index = 0
    hide_cursor()
    try:
        while True:
            block: list[str] = []
            for i, item in enumerate(rows):
                shortcut = f"{item.shortcut}) " if item.shortcut else ""
                label = f"{shortcut}{item.label}"
                if i == index:
                    block.append(paint(f"  {pointer} {label}", REVERSE + item.color))
                else:
                    block.append(paint(f"    {label}", item.color))
            drawn = _draw_menu(block, "↑/↓ move   Enter select   Esc back")

            key = read_key()
            if key == "ctrl-c":
                raise KeyboardInterrupt
            if key in {"esc", "q"}:
                return None
            if key == "up":
                index = (index - 1) % len(rows)
            elif key == "down":
                index = (index + 1) % len(rows)
            elif key == "enter" or key == "right":
                return rows[index].value
            else:
                for item in rows:
                    if item.shortcut is not None and key == item.shortcut:
                        return item.value

            _move_up(drawn)
    finally:
        show_cursor()


def confirm(question: str, *, default: bool = False) -> bool:
    print(paint(f"\n  {question}", YELLOW))
    picked = select(
        [
            Choice("yes", "Yes", GREEN, "1"),
            Choice("no", "No", RED, "0"),
        ]
    )
    if picked is None:
        return False
    if picked == "yes":
        return True
    if picked == "no":
        return False
    return default


def multi_select(choices: list[Choice], selected: set[str] | None = None) -> list[str]:
    picked = set(selected or [])
    rows = list(choices)
    index = 0
    hide_cursor()
    try:
        while True:
            block: list[str] = []
            for i, item in enumerate(rows):
                mark = "●" if item.value in picked else "○"
                label = f"{mark}  {item.label}"
                if i == index:
                    block.append(paint(f"  ❯ {label}", REVERSE + item.color))
                else:
                    block.append(paint(f"    {label}", item.color))
            block.append("")
            if index == len(rows):
                block.append(paint("  ❯ Done", REVERSE + GREEN))
            else:
                block.append(paint("    Done", WHITE))
            drawn = _draw_menu(block, "Space toggle   Enter confirm   Esc back")

            key = read_key()
            if key == "ctrl-c":
                raise KeyboardInterrupt
            if key in {"esc", "q"}:
                return sorted(picked)
            total = len(rows) + 1
            if key == "up":
                index = (index - 1) % total
            elif key == "down":
                index = (index + 1) % total
            elif key == "space" and index < len(rows):
                value = rows[index].value
                if value in picked:
                    picked.remove(value)
                else:
                    picked.add(value)
            elif key == "enter":
                if index == len(rows):
                    return sorted(picked)
                value = rows[index].value
                if value in picked:
                    picked.remove(value)
                else:
                    picked.add(value)
            _move_up(drawn)
    finally:
        show_cursor()


def _draw_menu(lines: list[str], hint: str) -> int:
    body = "\n".join(lines)
    footer = paint(f"  {hint}", DIM)
    text = f"{body}\n\n{footer}\n"
    sys.stdout.write(text)
    sys.stdout.flush()
    return text.count("\n")


def _move_up(lines: int) -> None:
    if lines < 1:
        return
    # Stay on column 0, then erase only the menu block — not the header above it.
    sys.stdout.write(f"\r\033[{lines}A\033[J")
    sys.stdout.flush()
