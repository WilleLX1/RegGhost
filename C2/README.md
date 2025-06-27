# RegGhost C2

RegGhost is a focused **Python-based Command & Control (C2)** component of our broader framework, providing a secure web dashboard, real-time client management, payload dispatch, and an interactive shell—all delivered via a minimal, extensible codebase.

---

## 🔹 Core C2 Functionality

* **Client Listener:** A TCP server accepts and tracks agent connections, capturing metadata (hostname, PID, OS) and maintaining live status.
* **Secure Web Dashboard:** Flask-based interface with session-driven authentication, featuring:

  * **Client Overview:** Live table of connected agents with IP, last check-in, and reachable status.
  * **Interactive Shell:** Real-time command input/output using Server-Sent Events (SSE).
  * **Module Invocation:** Select and launch C# payload modules directly against an agent.

---

## 🛠 Payload Modules

Modules are authored in C# and discovered automatically from the `modules/` directory. Each file must begin with a JSON metadata header:

```csharp
/*
{
  "name": "example_module",
  "desc": "Description of what this payload does",
  "author": "AuthorHandle",
  "version": "1.0",
  "args": ["arg1", "arg2"]
}
*/

public class Module {
    public static void Run(string[] args) {
        // implementation...
    }
}
```

**Metadata fields:**

* `name`: unique identifier
* `desc`: brief functionality overview
* `author`: module author
* `version`: semantic version
* `args`: ordered parameter names

Drop any compliant `.cs` file into `modules/`—it will appear in the dashboard for dispatch.

---

## 📊 Logging & Monitoring

* **Request Logging:** All dashboard actions and HTTP events are logged.
* **Agent Activity:** Client check-ins, commands sent, and output captured in rotating log files.
* **Audit Review:** Use standard Python `logging` with rotating handlers for both console and file outputs.

---

## 🔒 Security & Configuration

Sensitive values are controlled via environment variables; defaults are:

| Variable      | Purpose            | Default   |
| ------------- | ------------------ | --------- |
| `DASH_USER`   | Dashboard username | `admin`   |
| `DASH_PASS`   | Dashboard password | `secret`  |
| `MODULES_DIR` | Payload directory  | `modules` |

---

*This document exclusively covers the C2 server’s architecture and operations.*
*For details on the entire RegGhost project, [click here](../README.md).*
