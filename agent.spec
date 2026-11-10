# -*- mode: python ; coding: utf-8 -*-
# Build: pyinstaller agent.spec
# Prefer Linux Docker build for VPS binaries (see Dockerfile / make build).

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

_hidden = [
    'agent.cli',
    'agent.http',
    'agent.ops',
    'agent.runtime',
    'agent.worker',
    'agent.db',
    'agent.drivers.xray_http',
    # Async SQLite ORM stack (dialect driver is imported lazily from the URL).
    'aiosqlite',
    'aiomysql',
    'pymysql',
    'sqlalchemy.dialects.mysql',
    'sqlalchemy.dialects.mysql.aiomysql',
    'sqlalchemy.dialects.mysql.pymysql',
    'greenlet',
    'sqlalchemy.ext.asyncio',
    'sqlalchemy.dialects.sqlite',
    'sqlalchemy.dialects.sqlite.aiosqlite',
    'alembic',
    'alembic.command',
    'alembic.config',
    'alembic.runtime.migration',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
]
_hidden.extend(collect_submodules('agent.database'))
_hidden.extend(collect_submodules('agent.services'))
_hidden.extend(collect_submodules('alembic'))

a = Analysis(
    ['src/agent/__main__.py'],
    pathex=['src'],
    binaries=[('dist/pp-forward', '.')],
    datas=[
        ('alembic.ini', '.'),
        ('alembic', 'alembic'),
    ],
    hiddenimports=_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
