# Experimental configuration (supplementary to NCCY 2026 manuscript, Table 1)

Main dataset: 12 runs collected on 24 Aug 2026 (1 run per OS × scenario). Independent runs: Linux ransomware and trojan, 25 Aug 2026.
Every run starts from the same VM snapshot (`clean`); the scenario script is repeated until the run duration ends.

## Environment

| Item | Linux | Windows |
|---|---|---|
| Host | Windows 10, VMware Workstation, Vagrant | same |
| Target VM | Ubuntu 22.04 (`bento/ubuntu-22.04`), 2 vCPU, 4 GB | Windows 10 (`gusztavvargadr/windows-10`), 2 vCPU, 4 GB |
| Sensor | Sysmon for Linux (apt `sysmonforlinux`), config `provision/sysmon-config.xml`, schema 4.81 | Sysmon64 (Sysinternals download), config `provision/windows/sysmon-config-win.xml`, schema 4.90 |
| EventIDs observed | 1, 3, 4, 5, 9, 11, 23 | 1, 2, 3, 5, 8, 9, 11, 12, 13, 23 |
| Log transport | journald → rsyslog (TCP) → host | EVTX export at end of run |
| Protection | – | Defender real-time + Tamper Protection disabled |
| Atomic Red Team | Invoke-AtomicRedTeam + atomics from GitHub `master`, installed Aug 2026 (`provision/install_art.sh`) | same (`provision/windows/install_art_win.ps1`) |
| Run duration | 10 min | 11–16 min (scenario start → end in `*_meta.json`) |
| Label seed | `/tmp/lab_sandbox` | `C:\lab_sandbox` |
| Lab services | C2 server (`host/c2_server.py`) and mining pool (`host/mining_pool.py`) on the host | same |

## Atomic Red Team techniques and test numbers

"custom" = step written by the authors for the same technique (no Linux atomic test available); not an Atomic Red Team test.

| Scenario | Linux (`scenarios/*.sh`) | Windows (`scenarios_win/*.ps1`, Git HEAD) |
|---|---|---|
| Benign | scripted user activity (`benign.sh`) | scripted user activity, 30 iterations per round (`benign.ps1`) |
| Ransomware | T1083 #3,4,8; T1074.001 #2; T1486 #1,2,3,4; T1070.004 #1,2,3 | T1083 #1,2,5,9; T1005 #1; T1074.001 #1,3; T1486 #5,8,10; T1070.004 #4,5,6,7,10 |
| Trojan | T1082 #3,4; T1033 #2; custom: T1105, T1071.001, T1059.004, T1003, T1053.003, T1543.002 | T1082 #1,7,9,11,27,35; T1033 #1,4,5,6; T1057 #2–6; T1087.001 #8,9,10; T1059.001 #5,7,8; T1547.001 #1,2,8,9,11; T1053.005 #2,4,7,9; T1112 #1,6,7,40,41; T1005 #1; T1074.001 #1,3; T1027 #2,3,7,11; T1036.003 #1,3,5,7 |
| Botnet | T1016 #3; T1049 #4,5,6; T1071.001 #3; T1132.001 #1,2; T1105 #1,2,3,27 | T1016 #1,2,4,9; T1049 #1,2,3; T1018 #1,4,5; T1071.001 #1; T1132.001 #3; T1105 #7,9,10,15,16,25; custom beacon to lab C2 (30×) |
| Cryptominer | T1082 #4,5; T1057 #1; T1053.003 #1,2; custom: T1105, T1496 (miner to lab pool, 90 s) | T1082 #1,7,9,11,27,35; T1057 #2–6; T1105 #7,9,10,15,16,25; T1496 #2; T1053.005 #2,4,7,9; custom pool connections (20×) |
| Exploitation | T1082 #3,4,5; T1033 #2; custom: T1068, T1003.008, T1136.001, T1548 | T1069.001 #2,3,5,6; T1012 #1,2,3,6; T1497.001 #3,5; T1552.001 #4,5,13,14; T1548.002 #1,3,5,7,9; T1134.001 #1,2; T1134.002 #1; T1055 #3,4,6,7,11; T1218.011 #2,3,9 |

## Processes per run (= test-set composition of the leave-one-run-out folds)

| Run | label 1 | label 0 | lineage groups |
|---|---|---|---|
| Linux benign | 0 | 4,582 | 302 |
| Linux ransomware | 2,065 | 1,396 | 847 |
| Linux trojan | 735 | 1,881 | 1,006 |
| Linux botnet | 660 | 809 | 637 |
| Linux cryptominer | 61 | 321 | 138 |
| Linux exploitation | 2,079 | 3,713 | 1,685 |
| Windows benign | 0 | 2,437 | 62 |
| Windows ransomware | 436 | 203 | 99 |
| Windows trojan | 622 | 179 | 79 |
| Windows botnet | 786 | 128 | 82 |
| Windows cryptominer | 299 | 142 | 52 |
| Windows exploitation | 268 | 169 | 83 |
| Linux ransomware (independent, 25 Aug) | 619 | 539 | 295 |
| Linux trojan (independent, 25 Aug) | 375 | 1,057 | 552 |

Seeds: model `random_state=0`; lineage-grouped CV repeats use seeds 0–4. Code: `host/revised_experiments.py`.
