# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['Toolkit.py'],
    pathex=[],
    binaries=[],
    datas=[('tcp_client.py', '.'), ('tcp_server.py', '.'), ('tcp_proxy.py', '.'), ('udp_client.py', '.'), ('ssh_executor.py', '.'), ('ssh_command_handler.py', '.'), ('ssh_server.py', '.'), ('reverse_ssh_tunnel.py', '.'), ('packet_sniffer.py', '.'), ('port_scanner.py', '.'), ('arp_spoofer.py', '.'), ('mac_flooder.py', '.'), ('password_cracking.py', '.'), ('http_brute_forcer.py', '.'), ('log_analyser.py', '.'), ('requirements.txt', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SecurityToolkit',
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
