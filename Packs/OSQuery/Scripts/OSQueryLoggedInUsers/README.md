Deprecated. Use OSQueryBasicQuery with query='select liu.*, p.name, p.cmdline, p.cwd, p.root from logged_in_users liu, processes p where liu.pid = p.pid;' instead.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | OSQuery |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* OSQueryBasicQuery

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| system | The System to remote execute on, can be a list of systems |

## Outputs

---
There are no outputs for this script.
