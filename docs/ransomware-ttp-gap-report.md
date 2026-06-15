# Ransomware TTP Gap Report — 76 Families vs. Existing Detection Stack

**Scope**: Windows-observable TTPs across the 76 ransomware families listed in `RANSOM_NOTE_FILENAMES`. Sources: CISA #StopRansomware advisories, MITRE ATT&CK software/group pages, vendor reports (Sophos, SentinelLabs, Trend Micro, Talos, Microsoft, Cybereason). Existing detectors in winevt-analysis, pe-analysis, and srum-analysis are excluded.

**Evidence grading**:
- **High** — corroborated by CISA + MITRE + ≥1 vendor IR report, with concrete EID/field/string.
- **Medium** — single authoritative source (CISA, MITRE) or 2+ vendor reports.
- **Low** — single-vendor blog or inferred from cluster behaviour.

---

> ## Update — 2026-06-15 (currency review)
>
> Most of the gaps below have since been closed; this report now reads more as a
> **coverage map than a gap list**. Verified against the live `winevt-analysis`
> detector modules:
>
> - **All 10 of the §3 "high-priority detector proposals" now ship** as
>   `winevt-analysis` modules: `vssadmin_wmic` (proposals 1 + 3), `taskkill_av_cluster`
>   (2), `bcdedit_recovery` (4), `wevtutil_cl` (5), `defender_disable` (6),
>   `comsvcs_lsass` (7), `rmm_install` (8), `local_admin_creation` (9), `rdp_enable`
>   (10). See the Status column added to the §3 table.
> - **8 of the 10 "largest gaps"** in this summary are closed (mappings annotated
>   inline below); plus `service_stop_avset` (gap 3, `net stop`), and `wbadmin delete
>   catalog` is matched in `ps_patterns`.
> - **Genuine remaining gaps** (still unbuilt as of this review): GPO/SYSVOL XML
>   deployment (gap 7), domain-recon LOLBins `adfind`/`nltest`/`sharphound` (gap 10 —
>   `adexplorer_recon` covers AD Explorer only), the EDRKillShifter/Truesight/AuKill
>   driver-kill set (gap 5 — `byovd`/`zemana_driver_load` cover generic BYOVD only),
>   `rclone` exfil and `bitsadmin` download (§3 honorable mentions), and the ESXi
>   pivot detector (`detect_esxi_pivot`, §4 — no `Connect-VIServer`/`plink` coverage).
>
> The pre-update text below is retained as the historical baseline.

## Executive Summary

The existing stack covers Defender/HVCI tamper, BYOVD driver install (Zemana cluster), VSS deletion via the VSS Application channel, Hyper-V VM shutdown, scheduled task abuse, QWCrypt-specific PE/process IOCs, several LOLBin-WebDAV patterns, ransom-note write, AD Explorer recon, DLL sideload (srvcli/netutils), PowerShell history wipe, RPivot/Chisel, Impacket wmiexec, 7-Zip staging, fake-browser-update tasks, and workers.dev DNS. PE-analysis covers packers, injection-API clusters, ransomware strings, .NET anomalies, ransom-note filenames, AV-exclusion strings, network IOCs, credential strings, persistence strings, anti-debug, TLS callbacks, overlay, PE anomalies, dotnet anomalies. SRUM covers automated execution, beaconing, CPU dominance, exfil signal, suspicious paths, masquerade, phantom foreground, notification C2, selective gap, qwcrypt IOC.

**Largest gaps** (each appears across the majority of the 76 families):

1. **`vssadmin.exe delete shadows` / `wmic shadowcopy delete` command-line detector** — VSS detector already triggers on the VSS Application channel (8193/524), but the **process-creation command-line** signature (EID 4688 / Sysmon EID 1) is what fires across nearly every family that uses LOLBin VSS rather than the COM API. This is the single highest-coverage gap.
2. **`bcdedit /set ... recoveryenabled no` and `wbadmin delete catalog`** — recovery-inhibit pair distinct from VSS. Used by ≥30 families.
3. **Mass process termination via `taskkill /F /IM` or `net stop` over a target list** — Conti/LockBit/Royal/BlackCat/Phobos/Akira/BlackBasta/RansomHub/BianLian/Hive/MedusaLocker/Rhysida/Play all kill the same ~35-process AV/SQL/Veeam list.
4. **`wevtutil cl <log>` and `Clear-EventLog`** — log clearing via the command line. EID 1102 (Security cleared) is already covered indirectly, but the **execution** event is not, and many families clear by name (System/Application/Security) before EID 1102 is even written.
5. **EDRKillShifter / Truesight / AuKill style userland-from-driver kill chain** — RansomHub, BlackCat, BlackBasta, Medusa, BianLian, Play. Different driver set than BYOVD detector's allowlist.
6. **Mass RDP-enable via registry** — `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections=0` plus firewall rule `Remote Desktop`. ≥15 families.
7. **GPO-based mass deployment** — `Services.xml` / `NetworkShares.xml` / `ScheduledTasks.xml` written to SYSVOL. LockBit 3.0, Conti, Maze, BlackCat, BlackBasta, Royal.
8. **Mimikatz / comsvcs.dll MiniDump of LSASS** — covered for PE strings? not for the runtime EID 4688 / Sysmon 10 (process access) chain.
9. **Defender disablement via PowerShell `Set-MpPreference -DisableRealtimeMonitoring $true` / DISM `Remove-WindowsFeature Windows-Defender`** — string-matched in PE strings but not in EID 4104 PowerShell script-block channel.
10. **AdFind, `nltest /dclist`, `net group "Domain Admins"`** — domain recon LOLBins. ≥20 families.

---

## Section 1 — TTP matrix (concise)

Citations: `[C]` = CISA #StopRansomware, `[M]` = MITRE ATT&CK software/group page, `[V]` = vendor IR report. MITRE IDs cite the dominant technique observed; many families chain several.

| # | Family | Initial Access | Lateral Movement | Persistence | Pre-Encryption | Unique Windows Artifact | MITRE IDs |
|---|---|---|---|---|---|---|---|
| 1 | STOP/DJVU | Cracked-software bundles, malvertising [V] | n/a (commodity, single host) | Run key + scheduled task `Time Trigger Task` | Cleans Defender history, downloads Vidar | `%LocalAppData%\<guid>\<rand>.exe`; persistence task `Azure-Update-Task` | T1547.001, T1140 |
| 2 | LockBit 3.0 | Phishing, RDP, exploit (Citrix, F5, Fortinet) [C] | SMB, PsExec, GPO push (Services.xml/NetworkShares.xml) [C] | GPO scheduled task, registered service | `Win32_ShadowCopy.DeleteInstance` via WMI; `bcdedit safeboot network`; 35-proc kill list; safe-mode reboot | LockBit 3.0 Black icon `.ico` registered on `.lockbit` extension; GPO XML in SYSVOL | T1490, T1562.009, T1489 |
| 2g | LockBit Green | same | same | same as LB3 but Conti-derived code | identical to LB3 plus Conti-style WMI service | shares Conti mutex `kjasdf7637` artefact pattern | same |
| 3 | BlackCat/ALPHV | Stolen creds, exploit (ESXi), help-desk social-eng (Octo Tempest) [C][V] | PsExec, Impacket, RDP, AnyDesk | Local admin account, AnyDesk install | Rust binary; `--access-token`; PsExec `-accepteula`; clear Recycle Bin | `\\.\HARDDISKVOLUMESHADOWCOPY*` direct VSS read; CLI flag `--no-vm-kill` skip | T1486, T1059, T1218 |
| 4 | RansomHub | Citrix/Fortinet/Confluence CVEs, phishing [C] | RDP, PsExec, AnyDesk, Connectwise, N-Able, Cobalt Strike, Metasploit | New local accounts, re-enable disabled accounts | EDRKillShifter (BYOVD), Mimikatz, iisreset | `EDRKillShifter.exe`, driver `LDDP.sys`/`Truesight.sys` | T1486, T1562.001, T1068 |
| 5 | Conti | TrickBot/BazarLoader phishing, Log4Shell [C] | SMB, PsExec, WMI, Cobalt Strike | Service install, scheduled task | `nltest /dclist`, AdFind, `net group`, Rclone to MEGA | mutex `kjasdf7637`; `C:\Windows\<rand>.exe` self-copy | T1486, T1489, T1572 |
| 6 | Hive | Phishing, RDP, ProxyShell [C] | RDP, Cobalt Strike, BloodHound | Service install | `wevtutil cl system/security/application`, vssadmin, wmic shadowcopy | Pre-encryption `*.key` file in C:\, `HiveLeaks` mutex | T1486, T1490, T1070.001 |
| 7 | REvil/Sodinokibi | Kaseya VSA supply chain, JS phishing, RDP [M] | PsExec, Cobalt Strike | Registry Run key, service | Encodes config in JSON in PE resource; `vssadmin`, safe-mode trick | `SOFTWARE\<rand>` w/ encoded config under HKLM | T1486, T1547.001, T1562 |
| 8 | GandCrab | RIG/Fallout EK, phishing, RDP | n/a single host | Run key `HKCU\...\Run\<rand>` | `Process Hacker` to kill AV | mutex prefix `Global\pc_group=...` | T1486 |
| 9 | Cl0p | MOVEit (CVE-2023-34362), GoAnywhere, Accellion [C] | TrueBot/Cobalt Strike, FlawedAmmyy | Service `MSExchange Health Mgr` mimicry | `LemurLoot` WebShell on MOVEit; SQL injection | `human2.aspx` on MOVEit; `Get-Folders.aspx` | T1190, T1505.003, T1567 |
| 10 | Ryuk | TrickBot/Emotet phishing [C] | SMB, PsExec, WMI, Cobalt Strike | Run key, Wake-on-LAN to encrypt off systems | `vssadmin delete shadows`; kills AV; `nltest`; `bcdedit` | WoL magic packet `FF FF FF FF FF FF` + MAC; `RyukReadMe.txt` | T1486, T1490, T1059 |
| 11 | DarkSide/BlackMatter | RDP, phishing | PsExec, WMI, Cobalt Strike | Service install | `vssadmin Delete Shadows /All /Quiet`; SafeMode-style trick (BM only); kills AV | Custom packer w/ COM IPersistFile abuse for VSS delete | T1486, T1490 |
| 12 | Phobos | RDP brute force, Angry IP Scanner, SmokeLoader phishing [C] | RDP only | Run key + Startup folder, autorun scheduled task | `vssadmin delete shadows`, `wmic shadowcopy delete`, `netsh advfirewall set currentprofile state off`, `bcdedit /set {default} recoveryenabled no`, `wbadmin delete catalog -quiet`, `mshta info.hta` | `mshta` invoking `info.hta` in Desktop/Public/C:\ | T1490, T1562.004, T1547.001 |
| 13 | MedusaLocker | RDP, phishing [C] | SMB, GPO | Reg Run key + GPO scheduled task | Safe-mode boot trick (T1562.009); `vssadmin` | Lan-only LAN encryption beacon to subnet | T1562.009, T1486 |
| 14 | Maze | Spearphishing, exploit kit | Cobalt Strike, PsExec | Scheduled task | `vssadmin delete shadows`; `vssadmin resize shadowstorage 401MB` (forces VSS rollover) | resize-shadowstorage to evict copies w/o admin-context vssadmin delete | T1486, T1490 |
| 15 | Egregor | Cobalt Strike from Qakbot/IcedID [M] | RDP, Cobalt Strike, GPO | scheduled task | rundll32 of DLL w/ password CLI arg `-p`; `vssadmin` | DLL requires `-p <pw>` to decrypt payload | T1218.011, T1486 |
| 16 | DoppelPaymer | BazarLoader, Dridex phishing [M] | SMB, PsExec | Service | `Process Hacker` kill list; ProcessHacker driver `kprocesshacker.sys` (BYOVD) | `.locked` ext; CLI `-tdf` thread count | T1486, T1068 |
| 17 | WannaCry | EternalBlue (SMBv1 MS17-010) wormable [M] | SMBv1 worm | service `mssecsvc2.0` | killswitch URL DNS query | service name `mssecsvc2.0`, `tasksche.exe` in `%WINDIR%`, killswitch DNS | T1210, T1486 |
| 18 | Matrix | RDP brute force | n/a single host | Run key | `vssadmin`, `wmic shadowcopy delete`, `bcdedit`, deletes Recycle Bin | uses `cipher /w:` to wipe free space | T1486, T1561.002 |
| 19 | Dharma/CrySiS | RDP brute force [V] | Limited (manual RDP hops) | Run key + Startup folder; service | `vssadmin`, `wmic shadowcopy`, `wbadmin`, network share enum | drops Mimikatz `mim.exe` `mimi.exe` in `%TEMP%`, IP scanner `IS.exe` | T1486, T1110 |
| 20 | Hermes | Phishing, lateral via Cobalt Strike | SMB, PsExec | n/a | `vssadmin`, `bcdedit`, `wbadmin` | shares code base w/ Ryuk; HERMES marker in encrypted files | T1486 |
| 21 | SamSam | RDP brute force, JBoss exploit [M] | PsExec, NLBrute, xRDP | Manual deploy via PsExec | Manual VSS delete; manual AV kill | per-host build IDs `bat.bat` runs `samsam.exe -r` | T1110, T1486 |
| 22 | Locky | Necurs botnet, malicious JS macro phishing | n/a single host | Run key | `vssadmin Delete Shadows /All /Quiet` | Affid in registry `HKCU\Software\Locky\id` | T1486 |
| 23 | CryptoLocker | Gameover ZeuS botnet phishing | n/a single host | Run key `CryptoLocker` value | `vssadmin Delete Shadows` | C2 DGA-generated domains | T1486 |
| 24 | TeslaCrypt | Angler/Neutrino EK | n/a single host | Run key | `vssadmin`, `bcdedit` | `.ecc/.ezz/.exx/.xyz/.zzz/.aaa/.abc/.ccc/.vvv` ext rotation | T1486 |
| 25 | CTB-Locker | Spam (Dridex/Cutwail) | n/a single host | Run key, scheduled task | `vssadmin Delete Shadows`, deletes Tor binary from Temp | uses Tor proxy bundled in dropper | T1486 |
| 26 | Shade/Troldesh | Spam, RIG EK | n/a single host (some lateral via SMB) | Run key | `vssadmin Delete Shadows /All /Quiet`; installs xmrig | drops xmrig miner alongside ransom; `xtbl/no_more_ransom/breaking_bad` ext | T1486, T1496 |
| 27 | AvosLocker | ProxyShell, ProxyLogon, RDP brute force [V] | PsExec, AnyDesk, splashtop | Run key, AnyDesk service | safe-mode reboot trick; PDQ Deploy; Mimikatz | uses `--safeboot` flag; PDQ Deploy `pdqdeploy.exe` artefact | T1562.009, T1486 |
| 28 | BlackBasta | QakBot/Cobalt Strike phishing, Quick Assist social-eng [C][V] | BITSAdmin, PsExec, RDP, Splashtop, ScreenConnect, Cobalt Strike | Service install, AnyDesk | SoftPerfect netscan; Mimikatz; `vssadmin`; iisreset; safe-mode reboot | `dpapi.exe`; Microsoft Teams social-eng artefact; netscan `Intel`/`Dell` masquerade in `C:\` | T1486, T1562.001, T1059 |
| 29 | Lorenz | VoIP CVE (Mitel CVE-2022-29499), phishing | RDP, Cobalt Strike | scheduled task | `vssadmin`, `wevtutil`, ProDump LSASS | Mitel exploit chain artefact in TFTP logs (Linux side) | T1190, T1486 |
| 30 | Quantum | IcedID, Emotet phishing | Cobalt Strike, RDP, WMI | scheduled task | `vssadmin`, ADFind, Cobalt Strike | shares Conti TTP set; fast-encrypt mode `--fast` | T1486 |
| 31 | BianLian | RDP w/ valid creds (initial access), phishing [C] | RDP, PsExec; Ngrok/Rsocks proxies | Local admin accounts; AnyDesk/Atera/SplashTop/TeamViewer | Custom Go backdoor (PE Go binary); secretsdump.py; `dump.exe`, `exp.exe` (CVE-2020-1472 ZeroLogon) | `def.exe`, `system.exe`, `dump.exe`, `exp.exe`; Go-build PE signature | T1486, T1090, T1003 |
| 32 | Royal | Phishing (Callback/BatLoader), RDP, exposed apps [C] | RDP, PsExec, Cobalt Strike | New domain admin via batch script | `vssadmin delete shadows`; clears Application/System/Security event logs via batch; partial encryption via CLI `-percent` | Chisel client w/ `R:<ip>:43657:socks`; `.royal_w` ext; `conhost.exe` rename of Chisel | T1486, T1059.003, T1070.001 |
| 33 | Play | FortiOS CVE-2018-13379/CVE-2020-12812, ProxyNotShell, RDP [C] | PsExec, RDP | scheduled task | AdFind, Bloodhound, Mimikatz, Empire; Process Hacker; GMER; PowerTool | `Grixba` infostealer; SystemBC; SaveTheQueen webshell | T1486, T1003 |
| 34 | 8Base | Phobos derivative; phishing + SmokeLoader | RDP | Run key + scheduled task | identical to Phobos: vssadmin, wmic shadowcopy, bcdedit, wbadmin | drops `info.hta` and `info.txt` ransom notes (Phobos heritage) | T1486 (same as Phobos) |
| 35 | Akira | SSL VPN w/o MFA (Cisco ASA/FTD), phishing, valid creds [V] | RDP, AnyDesk, Cloudflared, SSH | Local accounts; AnyDesk, Cloudflared tunnel | Mimikatz, LaZagne; AdFind; Rclone/WinSCP to MEGA; `Veeam-Get-Creds.ps1` (CVE-2023-27532) | Cloudflared tunnel; `MEGAcmdServer.exe`; Akira-specific Tor URL hard-coded; ESXi Linux variant in Rust (Megazord) | T1486, T1190, T1567 |
| 36 | Rhysida | Compromised VPN creds w/o MFA, Gootloader [C] | RDP, PsExec, PowerView | scheduled task | `wevtutil cl` for system/application/security; AZCopy/StorageExplorer exfil; ipconfig/net group/whoami | AZCopy to attacker-Azure-blob; PowerView calls; ESXi variant | T1486, T1567.002 |
| 37 | INC Ransom | Spearphishing, valid creds, exploit (Citrix CVE-2023-3519) | RDP, PsExec, AnyDesk, MEGA | local accounts, scheduled task | `vssadmin`, AnyDesk, `wevtutil cl`, Lsassy | uses `--ens` CLI flag for full encrypt mode | T1486 |
| 38 | Hunters International | Hive successor; valid creds, phishing | RDP, Cobalt Strike | scheduled task | identical Hive flow: `wevtutil cl`, `vssadmin` | Rust rewrite of Hive; same affiliate panel | T1486 |
| 39 | Qilin/Agenda | Phishing, Citrix, valid creds | RDP, PsExec, PsRemote | scheduled task | safe-mode reboot trick; `vssadmin`; reboots to safe mode | Rust + Go variants; `--password` CLI required; `safeboot` reboot | T1486, T1562.009 |
| 40 | DragonForce | LockBit Black / Conti-derived; valid creds, phishing | RDP, PsExec | scheduled task | `vssadmin`, `bcdedit`, `wbadmin`; ESXi targeting | shares LockBit 3.0 builder leaked code | T1486 |
| 41 | BlackSuit | Royal successor; phishing, RDP [C] | RDP, PsExec, Cobalt Strike | New admin account via batch | identical Royal flow incl partial encryption; clears event logs | renames Chisel to `conhost.exe`; `wine.exe`/`f827.exe`/`b34v2.dll` artifacts | T1486, T1059.003 |
| 42 | Vice Society | RDP, phishing [C] | RDP, PowerShell remoting | scheduled task | PowerShell empire-style; `vssadmin`; AdFind; impacket | uses leaked HelloKitty/Five Hands code | T1486 |
| 43 | Sabbath/Eruption | Phishing (early), Cobalt Strike | Cobalt Strike, RDP | scheduled task | `vssadmin`; safe-mode trick (some samples) | tied to 54bb47h leak persona | T1486 |
| 44 | Karma | Manual ops; valid creds, exploit | Cobalt Strike, RDP | scheduled task | `vssadmin`, AdFind | derived from JSWorm/Nemty code | T1486 |
| 45 | Babuk | RDP, phishing | PsExec, Cobalt Strike | service install | `vssadmin Delete Shadows /All /Quiet`; safe-mode (Babuk Locker v2) | Babuk-builder source leak — fingerprint many derivatives | T1486 |
| 46 | Yanluowang | Compromised IT contractor creds (Cisco hack) | Cobalt Strike, RDP, SoftPerfect netscan | scheduled task | `vssadmin`; AdFind; PowerView; ConnectWise | uses `BazarLoader → BazarBackdoor → Yanluowang` chain | T1486 |
| 47 | Diavol | Conti gang attribution; TrickBot phishing | SMB, PsExec, WMI | service | `vssadmin`; differs from Conti by asymmetric-only RSA | uses Bitmap header magic in encrypted-file marker `WoOl` | T1486 |
| 48 | Ragnar Locker | Phishing, exploit (RDP, Citrix) | n/a (manual) | service `vboxservice` for VirtualBox guest [M] | Stops EDR by mass `taskkill` list; deploys VirtualBox VM containing encryptor [V] | `vbox*` driver/service creation + .vdi file in `%PROGRAMDATA%`; `sc create` for VirtualBox | T1564.006 (Run Virtual Instance), T1543.003 |
| 49 | FiveHands/HelloKitty | SonicWall CVE-2021-20016, RDP | PsExec, RDP, Cobalt Strike | scheduled task | `vssadmin`; signed driver `mhyprot2.sys` (Genshin Impact, BYOVD) | mhyprot2.sys BYOVD; `cmd.bat` w/ taskkill list | T1068, T1486 |
| 50 | Trigona | RDP brute force, valid creds | RDP, NetScan | scheduled task | `vssadmin`; Mimikatz; ADExplorer; SoftPerfect | `_FIRE_TRIGONA_*` filemarker; Tor-only payment | T1486 |
| 51 | Nevada | RDP, phishing | Cobalt Strike | scheduled task | `vssadmin`; uses Rust encryptor | dual Win/ESXi tooling | T1486 |
| 52 | Zeppelin | Phishing, RDP, RCE (BIG-IP) [V] | PsExec, RDP, Cobalt Strike | scheduled task | `vssadmin Delete Shadows`; `wmic shadowcopy delete`; `bcdedit`; multi-run resilience (re-runs after partial fail) | drops `notice.txt` on Desktop; CRC failures from re-encryption | T1486 |
| 53 | PYSA/Mespinoza | Phishing, RDP, exposed Citrix | PsExec, RDP | Empire/Cobalt Strike scheduled task | `vssadmin`, AdFind, secretsdump.py | `gtfobins.txt` Tor URL list dropped | T1486 |
| 54 | Monti | Conti-source-leak derivative; RDP, Log4Shell | PsExec, RDP, Cobalt Strike | service | identical Conti flow incl `nltest`, AdFind, Rclone | reuse of leaked Conti source — same mutex pattern | T1486 |
| 55 | NoEscape | RDP, phishing, exposed services | PsExec, RDP | scheduled task | `vssadmin`; safe-mode trick; `wevtutil cl` | shared codebase w/ Avaddon (leaked); affiliate-tier `.config` | T1486, T1562.009 |
| 56 | ESXiArgs | OpenSLP CVE-2021-21974 against unpatched ESXi (Linux only) | Lateral via SSH on ESXi from Windows admin host | n/a | Stops ESXi VMs via `vim-cmd vmsvc/power.off`; encrypts `.vmdk` | Pure Linux/ESXi — Windows-side only via admin staging host SSH logs | T1486, T1561.002 |
| 57 | CrossLock | Newer; phishing, RDP | RDP, PsExec | scheduled task | `vssadmin`; safe-mode | Go-built PE; signed cert masquerade | T1486 |
| 58 | RAGroup | Compromised creds, RDP | PsExec, Cobalt Strike | scheduled task | `vssadmin`; Babuk-leak derivative | reuses Babuk codebase | T1486 |
| 59 | MalasLocker | Zimbra CVE-2022-27926 | n/a (Linux-side primarily) | n/a | encrypts in-place; demands charity-donation proof | Mostly Linux Zimbra — Windows-side via Zimbra Win admin host | T1486 |
| 60 | Cuba | Hancitor phishing, exposed RDP [V] | PsExec, Cobalt Strike | service install `RDPSession` | Hancitor → BUGHATCH → Cobalt Strike; `vssadmin` | `BUGHATCH` loader; `Wedgecut` host-enum; `mimikatz` | T1486 |
| 61 | Nokoyawa | Karma-derivative; phishing, exposed RDP | RDP, Cobalt Strike | scheduled task | `vssadmin`; CL0P-style data-only extortion variant | shares Karma/JSWorm base | T1486 |
| 62 | Rorschach/BabLock | DLL sideload via signed `cy.exe` (Cortex XDR) [V] | Manual via Cobalt Strike | scheduled task GPO | DLL sideload abusing Palo Alto signed dumper `cy.exe → cyserver.exe → winutils.dll`; `vssadmin` | Sideloading via `cy.exe`; fastest known encryptor benchmark | T1574.002, T1486 |
| 63 | Cylance | Phishing | RDP | scheduled task | `vssadmin`; uses C++ implementation | small affiliate set | T1486 |
| 64 | Avaddon | Phishing JS macro | RDP, PsExec | Run key | `vssadmin`; clear Recycle Bin; safe-mode | aff-ID encoded in mutex `0x40` prefix | T1486, T1562.009 |
| 65 | Prometheus | THANOS-builder fork | RDP, Cobalt Strike | scheduled task | `vssadmin`, `wevtutil`; safe-mode | uses Thanos builder leaked features | T1486 |
| 66 | Grief/PayOrGrief | DoppelPaymer rebrand; phishing | PsExec, Cobalt Strike | service | `vssadmin`; ProcessHacker BYOVD | shares DoppelPaymer infrastructure | T1486 |
| 67 | MountLocker | Phishing, RDP | PsExec, Cobalt Strike, AdFind | scheduled task | AdFind, Cobalt Strike, `vssadmin`; recycle-bin clear | `mountlocker.bat` for AD pre-enum | T1486 |
| 68 | Thanos | Builder kit (RaaS-builder) | varies | varies | `vssadmin`; auto-spread USB option in builder; safe-mode option | unique among builders: USB-spread option toggleable | T1091, T1486 |
| 69 | NetWalker/Mailto | Phishing, Citrix CVE-2019-19781, RDP | PsExec, Cobalt Strike | reflective DLL injection into explorer.exe via PowerShell | PowerShell reflective injection (no PE on disk); `vssadmin`; AdFind | inline PowerShell loader; no encryptor PE persisted | T1059.001, T1486 |
| 70 | DearCry | Microsoft Exchange ProxyLogon (CVE-2021-26855) | Single-host via Exchange | service `msupdate` | service install `msupdate`; no recovery wipe | service name `msupdate`; minimal pre-encrypt flow | T1505.003, T1486 |
| 71 | Cheerscrypt | Exploited ESXi (Log4Shell) | SSH/ESXi shell | n/a | Pure Linux ESXi target | Linux only — Windows-side via admin host SSH | T1486 |
| 72 | AtomSilo | Confluence CVE-2021-26084 | PsExec | scheduled task | DLL sideload via `Bdservicehost.exe` (BitDefender signed) | sideloads `log.dll` via Bdservicehost | T1574.002, T1486 |
| 73 | Knight/Cyclops | Phishing, RDP, malspam | RDP, PsExec | scheduled task | `vssadmin`; Cyclops Blink rebrand to Knight | encrypted-file marker `KNIGHT` | T1486 |
| 74 | Pandora | REvil-derivative; phishing, RDP | PsExec, Cobalt Strike | scheduled task | `vssadmin`; signed driver BYOVD | REvil-source-leak heritage | T1486 |
| 75 | Mindware | SFile / Mindware shared codebase | RDP | scheduled task | `vssadmin`; safe-mode | shared infrastructure w/ SFile | T1486 |
| 76 | QWCrypt/RedCurl | Spearphishing → CHM/LNK chain | manual lateral RedCurl-style | scheduled task `ADNotificationManager` | excludeVM hypervisor pre-flight; Zemana BYOVD; rbcw.exe | already detected by `qwcrypt_proc`, `qwcrypt_pe_iocs`, `zemana_driver_load`, `hyperv_vm_shutdown`, `ps_qwcrypt_patterns` | T1486, T1068 |

---

## Section 2 — Common TTPs not yet detected (≥5 families, with EID + pattern)

For each: count out of 76, evidence quality, and the EVTX channel/field/value that would detect it.

### 2.1 LOLBin VSS deletion via process-creation (`vssadmin delete shadows`)

- **Count**: ~60/76 families [High]
- **MITRE**: T1490 Inhibit System Recovery
- **EID/source**: Security EID **4688** (Process Creation) `NewProcessName` ends in `\vssadmin.exe` AND `CommandLine` contains `delete shadows`; OR Sysmon EID **1** `Image` ends `\vssadmin.exe` AND `CommandLine` contains `delete shadows`.
- **Why existing `detect_vss_deletion` is insufficient**: That detector watches the VSS Application channel (8193/524) which fires when the VSS service itself is involved; many ransomware families invoke `vssadmin.exe` directly under a non-SYSTEM session, generating EID 4688 but no 8193/524 unless `Microsoft-Windows-VolumeSnapshot-Driver` is configured. The 4688/Sysmon-1 path is the high-fidelity catch.
- **Pattern**: `(NewProcessName|Image) ∈ {\vssadmin.exe, \wmic.exe} ∧ CommandLine =~ /(delete shadows|shadowcopy delete)/i`
- **FP risk**: Low. Legitimate `vssadmin delete shadows` is rare on user endpoints; backup admins occasionally run it. Filter on parent ≠ `wbadmin.exe`/`backup-product.exe`.

### 2.2 `wmic shadowcopy delete` LOLBin

- **Count**: ~45/76 families [High] (Phobos, Hive, LockBit, Conti, Ryuk, BlackCat, BlackBasta, Royal, Akira, BianLian, RansomHub, Medusa, etc.)
- **EID/source**: EID 4688/Sysmon 1, `Image` ends `\wmic.exe`, `CommandLine` contains `shadowcopy` AND (`delete` OR `/nointeractive`)
- **Pattern**: also catch the Microsoft-Windows-WMI-Activity Operational EID **5857** (provider load) followed by an EID **5861** (consumer fire) when paired w/ `Win32_ShadowCopy` query class
- **FP risk**: Very low.

### 2.3 `bcdedit recoveryenabled no` / `bootstatuspolicy ignoreallfailures`

- **Count**: ~35/76 [High] (Phobos, Hive, Conti, Ryuk, BlackCat, Royal, LockBit, Maze, Zeppelin, BlackSuit, etc.)
- **EID/source**: EID 4688/Sysmon 1, `Image` ends `\bcdedit.exe`, `CommandLine` contains any of `recoveryenabled no`, `bootstatuspolicy ignoreallfailures`, `safeboot`
- **Pattern**: `Image =~ /bcdedit\.exe$/ ∧ CommandLine =~ /(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures|safeboot)/i`
- **FP risk**: Very low. bcdedit is almost never run interactively outside IT.

### 2.4 `wbadmin delete catalog` (backup catalog wipe)

- **Count**: ~25/76 [High]
- **EID/source**: EID 4688/Sysmon 1, `Image` ends `\wbadmin.exe`, `CommandLine` matches `delete (catalog|systemstatebackup|backup)`
- **FP risk**: Low — legitimate use case is forgotten-backup cleanup by admins.

### 2.5 `wevtutil cl <log>` / `Clear-EventLog`

- **Count**: ~30/76 [High] (Hive, Royal, BlackSuit, Rhysida, INC, Lorenz, Quantum, Akira, Babuk derivatives)
- **EID/source**: EID 4688/Sysmon 1, `Image` ends `\wevtutil.exe`, `CommandLine` matches `cl (System|Application|Security|Setup|Microsoft-Windows-PowerShell)`. Plus PowerShell EID **4104** (script block) containing `Clear-EventLog` or `wevtutil cl`. Plus the Security channel's own EID **1102** ("audit log was cleared") and System channel EID **104** (other log cleared).
- **Note**: existing `winevt-analysis` has anti_forensics `detect_log_clearing` that checks EID 1102/104 (per source). What is missing is the **execution-side** detector that catches the `wevtutil.exe` command line before/independent of the cleared log writing 1102 — critical because clearing Application or System (not Security) does NOT produce 1102.
- **Pattern**: `(Image =~ /wevtutil\.exe$/ ∧ CommandLine =~ /\bcl\s+/i) ∨ (EID==4104 ∧ ScriptBlockText =~ /(Clear-EventLog|wevtutil\s+cl)/i)`

### 2.6 Mass process-kill via `taskkill /F /IM <name>` over AV/SQL/Veeam list

- **Count**: ~55/76 families [High]
- **MITRE**: T1489 Service Stop, T1562.001 Disable or Modify Tools
- **EID/source**: EID 4688/Sysmon 1 `Image` ends `\taskkill.exe`, `CommandLine` contains `/IM` and one of the target names (see Section 6). Cluster signal: ≥5 distinct taskkill invocations within 60s. Also EID 4688 `\net.exe stop <svc>` with svc ∈ {MSSQL, MSExchangeIS, vss, Veeam*, GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr, BackupExec*, memtas, mepocs, sophos*}.
- **Pattern (kill list bias)**: see Section 6 for the canonical list.
- **FP risk**: Medium for single taskkill; **very low** for a cluster of ≥5 against the canonical kill-list names within 60s.

### 2.7 Safe-mode reboot trick (`bcdedit /set {current} safeboot network`)

- **Count**: ~12/76 families [High] (LockBit 3.0, MedusaLocker, AvosLocker, Babuk v2, Avaddon, Qilin, NoEscape, Prometheus, Mindware, REvil under some campaigns)
- **EID/source**: EID 4688/Sysmon 1 `Image` ends `\bcdedit.exe`, `CommandLine` matches `safeboot` AND a subsequent `shutdown.exe /r /f /t 0` within 5 min; OR the System channel EID **6005** (EventLog start) following a service-control-manager EID 7036 transition with safeboot bit. Plus Security EID **4616** (system time change) sometimes precedes.
- **Pattern**: `bcdedit ... safeboot` + `shutdown /r` within 5 min on same host.
- **FP risk**: Very low. Legitimate safe-mode boot is interactive (msconfig.exe → boot tab); rarely via bcdedit CLI.

### 2.8 RDP enablement via registry (`fDenyTSConnections=0`) + firewall rule

- **Count**: ~15/76 families [High] (Snatch, BianLian, Phobos, BlackCat, Akira, Royal, Phobos derivatives, RansomHub, INC)
- **EID/source**: Sysmon EID **13** (registry value set) `TargetObject` matches `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`, `Details` = `DWORD (0x00000000)`. Plus EID **2004** (firewall rule added) or EID **2005** (modified) in `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` log with rule name containing `Remote Desktop` or `File and Printer Sharing`. Plus `netsh advfirewall firewall add rule` via EID 4688.
- **FP risk**: Low. Production RDP-enable is typically pre-deployed via GPO, not interactive registry write.

### 2.9 `comsvcs.dll MiniDump` LSASS dump (and direct MiniDumpWriteDump from rundll32)

- **Count**: ~25/76 families [High]
- **MITRE**: T1003.001
- **EID/source**: Sysmon EID **10** (process access) `SourceImage` ∈ {rundll32.exe, powershell.exe, taskmgr.exe (rare ransomware)}, `TargetImage` ends `\lsass.exe`, `GrantedAccess` includes `0x1010` or `0x1410` or `0x1438`; AND EID 4688/Sysmon 1 `CommandLine` matches `rundll32.*comsvcs.dll.*MiniDump` OR `procdump.*lsass` OR `nanodump`.
- **Pattern**: `(Image =~ /rundll32\.exe/ ∧ CommandLine =~ /comsvcs\.dll.*MiniDump/i) ∨ (Sysmon-10 TargetImage =~ /lsass\.exe$/ ∧ GrantedAccess ∈ {0x1010,0x1410,0x1438,0x143A})`
- **FP risk**: Low for Sysmon-10 cluster; rundll32+comsvcs is essentially always malicious.

### 2.10 `Set-MpPreference -DisableRealtimeMonitoring` / Defender disablement

- **Count**: ~30/76 [High]
- **EID/source**: PowerShell EID **4104** (script block) matches `Set-MpPreference.*-Disable*`, `Add-MpPreference.*-Exclusion`. Also Sysmon EID 13 watching `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\` values `DisableAntiSpyware`, `DisableAntiVirus`. Also Defender Operational EID **5001** (real-time off) and EID **5007** (config changed).
- **FP risk**: Low. Defender ops EIDs are the highest-fidelity catch.

### 2.11 AdFind / nltest / SharpHound domain reconnaissance LOLBin

- **Count**: ~25/76 [High]
- **EID/source**: EID 4688/Sysmon 1 `Image` ∈ {adfind.exe, AdFind.exe (rename-resistant: hash known)}, OR `Image` ends `\nltest.exe` AND `CommandLine` matches `/dclist|/domain_trusts`, OR `CommandLine` matches `net group "Domain Admins" /domain`, `net group "Enterprise Admins" /domain`. SharpHound: Sysmon EID 1 `CommandLine =~ /-CollectionMethod All/`, file write Sysmon EID 11 of `*.zip` containing `<domain>_<timestamp>.zip` to Temp.
- **FP risk**: Medium for `net group` (admins use it). Low for AdFind/SharpHound/nltest /dclist combo.

### 2.12 Rclone exfil to cloud (`rclone.exe ... --config ... mega:` or `b2:`)

- **Count**: ~20/76 [High] (BianLian, Conti, BlackCat, BlackBasta, Akira, Black Suit, INC, Hunters International, Royal, Vice Society)
- **EID/source**: EID 4688/Sysmon 1 `Image` matches `\rclone.exe$` or rename heuristic (PE imports `librclone`/Go-build w/ `rclone` strings); OR Sysmon EID **22** (DNS) `QueryName` matches `*.mega.nz`, `*.mega.co.nz`, `*.backblazeb2.com`, `*.b-cdn.net`, `*.dropboxapi.com` from non-browser process. OR Sysmon EID **3** (network connect) to known Mega/B2 IP ranges from non-browser.
- **FP risk**: Medium without rename detection; rclone has legitimate use. Combine with cloud-DNS-from-non-browser.

### 2.13 GPO-based mass deployment (`Services.xml`, `ScheduledTasks.xml` to SYSVOL)

- **Count**: ~10/76 [High] (LockBit 3.0, Conti, Maze, BlackCat, BlackBasta, Royal, Rorschach)
- **EID/source**: Sysmon EID **11** (file create) `TargetFilename` matches `\\<dc>\SYSVOL\<domain>\Policies\{*}\Machine\Preferences\(Services|ScheduledTasks|NetworkShares)\(Services|ScheduledTasks|NetworkShares)\.xml` from non-`gpme.exe`/non-`gpmc.msc` parent. Plus Security EID **5145** on DC: detailed share access to SYSVOL with `AccessMask` write.
- **FP risk**: Very low. SYSVOL writes are extremely rare outside GP authoring; legitimate writes come from gpme.exe under a Group Policy Admin context.

### 2.14 RMM tool installation (AnyDesk, Atera, Splashtop, ScreenConnect, Quick Assist, NetSupport, TeamViewer)

- **Count**: ~25/76 [High] (BlackBasta, RansomHub, Royal, BianLian, Akira, Rhysida, INC, Hunters Intl, Quantum, Snatch, BlackCat)
- **EID/source**: Sysmon EID 11 install of any of: `AnyDesk.exe`, `AteraAgent.exe`, `Splashtop*`, `ScreenConnect.ClientService.exe`, `ConnectWiseControl*`, `quickassist.exe` (Win11 binary present already; flag launch from non-interactive parent), `Atera*Setup*`, `TeamViewer_Setup*`, `NetSupportManager*`. Plus EID 7045 service creation with names matching. Plus EID 4688 firstrun.
- **FP risk**: Medium in IT-friendly environments. Bias toward: install path not under `Program Files`, install parent ∉ {msiexec.exe spawn from Software-Center}, time of install correlated w/ ransomware indicators.

### 2.15 `iisreset /stop` for backup interruption

- **Count**: ~8/76 [Medium] (BlackBasta, RansomHub, Royal, Black Suit, Akira, INC) — used when Veeam Backup & Replication's IIS-hosted services need to be stopped to release file locks before encryption
- **EID/source**: EID 4688/Sysmon 1 `Image` ends `\iisreset.exe`, `CommandLine` matches `/stop|/restart|/noforce`
- **FP risk**: Low on non-web-server hosts; medium on actual IIS hosts. Combine with `taskkill veeam` proximity.

### 2.16 New local administrator account creation + group add

- **Count**: ~20/76 [High] (BianLian, Royal, RansomHub, BlackCat, Phobos, BlackBasta, Akira, INC, Rhysida)
- **EID/source**: Security EID **4720** (account created) + EID **4732** (member added to local Administrators), or EID **4728** (member added to global Administrators). Plus Sysmon EID 1 `net user <name> <password> /add` and `net localgroup administrators <name> /add`.
- **FP risk**: Low — net user/localgroup is rarely used outside IT; combine w/ subsequent RDP-enable or RMM install.

### 2.17 Volume Shadow read via `\\.\HARDDISKVOLUMESHADOWCOPY*`

- **Count**: ~12/76 [Medium] (BlackCat/ALPHV explicitly documented; Conti, Akira, BianLian indirectly via secretsdump/Impacket; Volt Typhoon NTDS.dit path)
- **EID/source**: Sysmon EID **9** (RawAccessRead) `Device` matches `\Device\HarddiskVolumeShadowCopy*` from non-`VSSVC.exe`/`svchost.exe` process; OR `vshadow.exe` invocation; OR Sysmon EID 1 `CommandLine =~ /HARDDISKVOLUMESHADOWCOPY/i`.
- **FP risk**: Very low.

### 2.18 LDAP/AD recon via `dsquery` / `dsget` / `ldapsearch`-style

- **Count**: ~15/76 [Medium]
- **EID/source**: EID 4688 `Image` ∈ {dsquery.exe, dsget.exe, csvde.exe, ldifde.exe}; Directory Service EID **1644** (expensive LDAP search) on DC w/ Search-FilterClient pointing to non-admin host.
- **FP risk**: Medium for dsquery (legit admin use); 1644 to unusual client is high-fidelity.

### 2.19 Time service / `w32tm` tampering and OS time skew

- **Count**: ~7/76 [Medium] — observed in Snatch, BlackCat, and some Conti-derivative kill-chain steps to evade time-based detections and skew event timestamps
- **EID/source**: Security EID **4616** (System time changed) `Subject` ≠ SYSTEM AND magnitude > 5 min. Plus EID 4688 `\w32tm.exe`, `\net.exe time \\`, `tzutil`.
- **Note**: `anti_forensics.rs` already has `TimeSkew` via `EID_W32TIME_NTP_FAILED`; this proposed detector is the **active-tamper** complement, distinct from passive NTP-failed.
- **FP risk**: Low.

### 2.20 BITSAdmin / certutil download stagers

- **Count**: ~18/76 [High] (BlackBasta, Conti, Ryuk, BianLian, Royal, RansomHub)
- **EID/source**: EID 4688/Sysmon 1 `Image` ∈ {bitsadmin.exe, certutil.exe}, `CommandLine` matches `(transfer|/transfer|-urlcache|/urlcache).*http`. Plus Microsoft-Windows-Bits-Client Operational EID **3** (job created), EID **59** (job transferred), EID **60** (job complete) with `RemoteName` over plain HTTP or to non-Microsoft host.
- **FP risk**: Low for certutil-with-URL. Medium for BITS (Windows Update uses BITS); EID 60 with non-Microsoft `RemoteName` is high-fidelity.

---

## Section 3 — High-priority new detector proposals (top 10)

Ranked by (families covered) × (evidence quality) × (low FP).

> **Status (2026-06-15): all 10 implemented.** Each now ships as a `winevt-analysis`
> module — 1 + 3 → `vssadmin_wmic`, 2 → `taskkill_av_cluster`, 4 → `bcdedit_recovery`,
> 5 → `wevtutil_cl`, 6 → `defender_disable`, 7 → `comsvcs_lsass`, 8 → `rmm_install`,
> 9 → `local_admin_creation`, 10 → `rdp_enable`. Honorable mentions are mixed:
> `wbadmin` ✅ (`ps_patterns`), `certutil` ✅ (`explorer_lolbin` / `webdav_lolbin`);
> `rclone`, `gpo_sysvol_xml`, `adfind/sharphound`, `bitsadmin` remain ⬜ open.

| Rank | Detector | MITRE | Families | Source | EID | Field + Pattern | FP Risk |
|------|----------|-------|----------|--------|-----|-----------------|---------|
| 1 | `detect_vssadmin_cli` | T1490 | ~60 | Security/Sysmon-1 | 4688/1 | `Image~/vssadmin\.exe$/ ∧ CommandLine~/delete shadows/i` | Low |
| 2 | `detect_taskkill_av_cluster` | T1562.001, T1489 | ~55 | Security/Sysmon-1 | 4688/1 | `Image~/taskkill\.exe$/ ∧ CommandLine~/\/IM\s+(<KILL_LIST>)/i` w/ cluster threshold ≥5 in 60s | Very Low at cluster |
| 3 | `detect_wmic_shadowcopy_delete` | T1490 | ~45 | Security/Sysmon-1 | 4688/1 | `Image~/wmic\.exe$/ ∧ CommandLine~/shadowcopy.*(delete|\/nointeractive)/i` | Very Low |
| 4 | `detect_bcdedit_recovery_tamper` | T1490, T1562.009 | ~35 | Security/Sysmon-1 | 4688/1 | `Image~/bcdedit\.exe$/ ∧ CommandLine~/(recoveryenabled\s+no\|bootstatuspolicy\s+ignoreallfailures\|safeboot)/i` | Very Low |
| 5 | `detect_wevtutil_cl_execution` | T1070.001 | ~30 | Security/Sysmon-1/PS-4104 | 4688/1/4104 | `Image~/wevtutil\.exe$/ ∧ CommandLine~/\bcl\s+/i` OR `ScriptBlockText~/Clear-EventLog/i` | Very Low |
| 6 | `detect_defender_disable_powershell` | T1562.001 | ~30 | PS/Defender | 4104/5001/5007 | `ScriptBlockText~/(Set-MpPreference.*-Disable.*\|Add-MpPreference.*-Exclusion)/i` OR Defender EID 5001 transition to off | Low |
| 7 | `detect_comsvcs_lsass_dump` | T1003.001 | ~25 | Sysmon-10/Sysmon-1 | 1/10 | `(Image~/rundll32\.exe$/ ∧ CommandLine~/comsvcs\.dll.*MiniDump/i) ∨ (TargetImage~/lsass\.exe$/ ∧ GrantedAccess∈{0x1010,0x1410,0x1438,0x143A})` | Low |
| 8 | `detect_rmm_install` | T1219 | ~25 | Sysmon-11/EID 7045 | 11/7045 | file create of {AnyDesk,Atera,Splashtop,ScreenConnect,ConnectWise,TeamViewer,quickassist}.exe in non-`Program Files` paths AND parent ∉ trusted installer | Medium (tunable allowlist) |
| 9 | `detect_local_admin_creation` | T1136.001, T1098 | ~20 | Security | 4720+4732 | EID 4720 followed by EID 4732 adding new account to BUILTIN\Administrators within 60s; OR `net user ... /add` + `net localgroup administrators ... /add` chain | Low |
| 10 | `detect_rdp_enable_registry` | T1021.001, T1112 | ~15 | Sysmon-13/Firewall | 13/2004/2005 | Sysmon-13 `TargetObject~/Terminal Server\\fDenyTSConnections$/ ∧ Details~/0x00000000/` OR Firewall EID 2004/2005 rule `Remote Desktop` enabled | Low |

**Honorable mentions (rank 11–15)**: `detect_wbadmin_delete_catalog` (T1490, ~25 families); `detect_rclone_exfil` (T1567.002, ~20); `detect_gpo_sysvol_xml_write` (T1484.001, ~10, very high fidelity); `detect_adfind_sharphound` (T1018, ~25); `detect_bitsadmin_certutil_download` (T1105, ~18).

---

## Section 4 — ESXi-specific gap (ESXiArgs, Cheerscrypt, and the ESXi-targeting cluster)

**Pure-Linux families** (no Windows-side execution of the encryptor): ESXiArgs (CVE-2021-21974 OpenSLP), Cheerscrypt (Log4Shell against ESXi-adjacent), MalasLocker (Zimbra), plus the **Linux/ESXi variants** of Akira, BlackCat, BlackBasta, BianLian, Lockbit Green, BlackSuit, Royal, DragonForce, Nevada, Hunters International, RAGroup, Hive, Rhysida, Qilin, REvil, Babuk-leak derivatives.

**What is visible from Windows EVTX** (before/during ESXi deployment):

1. **SSH client launch on Windows admin host** — Sysmon EID 1 `Image` ends `\OpenSSH\ssh.exe`, `\Program Files\PuTTY\plink.exe`, `\PuTTY.exe`, with `CommandLine` containing the ESXi host's IP/hostname or username `root@`. **Detection approach**: enumerate Sysmon-1 of `(ssh|plink|putty)\.exe` whose destination matches a known vCenter/ESXi subnet (configurable) or whose CommandLine contains `root@` / `vmware` / `vmkernel`. Evidence quality: **High** — this is the canonical pivot from Windows admin to ESXi.
2. **vCenter / ESXi management web UI access from Windows browsers** — Sysmon EID 22 (DNS) or EID 3 (network) to vCenter on port 443 from non-browser process; also EID 4624 logon-type 3 on the Windows admin host preceded/followed by browser process.
3. **VMware PowerCLI invocation** — PowerShell EID 4104 `ScriptBlockText` contains `Connect-VIServer`, `Stop-VM`, `Set-VM`, `Get-VM`. Used legitimately by VMware admins but rare; combined with PsExec/RDP from non-admin host = high-fidelity.
4. **`vmrun.exe` / `vcli` invocations** — Sysmon EID 1 `Image` ends `\vmrun.exe` or `\vsphere-cli` w/ commands `stopAll`, `suspend`, `deleteVM`.
5. **vCenter credential theft on Windows** — Sysmon EID 11 file write of `%APPDATA%\VMware\credstore\*.xml` read by non-VMware process; EID 4688 process accessing `%APPDATA%\VMware\VMware vSphere Web Client\*.cfg`.
6. **Veeam Backup & Replication credential dump** — `Veeam-Get-Creds.ps1` (CVE-2023-27532) — PowerShell EID 4104 containing `[Veeam.Backup.Core.CDbCryptoKey]` or `Veeam.Backup.Common.dll` Reflection.Assembly load. Heavily abused by **Akira**, **Cuba**, **EstateRansomware**.

**Detector proposal (priority)**: `detect_esxi_pivot` — combination signal:
- (a) PowerShell EID 4104 containing `Connect-VIServer`/`Veeam.Backup` reflection, OR
- (b) Sysmon EID 1 `(ssh|plink|putty)` with destination in vCenter/ESXi management range, OR
- (c) Sysmon EID 11 read of VMware credstore from non-VMware parent.

Coverage: ESXiArgs / Cheerscrypt themselves leave no Windows EVTX (pure Linux). The detectable signal is the **Windows-side pivot** before the SSH/exploit. Coverage of the ESXi-targeting cluster (the ~17 hybrid families) is **High**; coverage of true Linux-only families (ESXiArgs/Cheerscrypt/MalasLocker) is structurally limited to the admin staging host.

**Hyper-V vs ESXi**: existing `detect_hyperv_vm_shutdown` covers VMMS 13002/13003 on Hyper-V hosts. There is **no equivalent for ESXi-by-proxy from Windows**; the closest is PowerCLI `Stop-VM` in EID 4104 — proposed as a sub-rule of `detect_esxi_pivot`.

---

## Section 5 — PE-level gaps (≥5 families, beyond existing pe-analysis)

Existing PE coverage is broad. The gaps are:

### 5.1 Rust-built encryptor PE fingerprint

- **Families**: BlackCat/ALPHV, Akira (Megazord Linux variant + Win), Hive (Hunters International rewrite), Nevada, Cuba (partial), Cylance, Rorschach (parts), DragonForce, INC (some samples), Qilin
- **PE indicators**:
  - `.rdata`/`.text` strings: `core::panicking::panic`, `core::fmt::Arguments`, `std::sys_common::backtrace`, `RUST_BACKTRACE`, `rustc_demangle`
  - Import: `bcrypt.dll` (BCryptGenRandom, BCryptOpenAlgorithmProvider) typical Rust crypto path
  - Compiler artifact: PDB path matches `.cargo\registry\src\...` or `target\release\<crate>`
  - Section name oddity: `_CONST` / `__rustc` (rare but present in -Cforce-frame-pointers builds)
- **Why it matters**: Rust ransomware bypasses string-based detectors because std-formatted output rarely contains the classic "ransom"/"bitcoin"/"decrypt" strings inline; the strings are in a separate `.rdata` blob accessed via `core::str::from_utf8`. PE-side Rust detection is a high-leverage gap. **Evidence: High** (vendor-corroborated for BlackCat, Akira, Hunters International).

### 5.2 Go-built ransomware fingerprint

- **Families**: BianLian (Go backdoor + early encryptor), CrossLock, Hive (Go variant pre-Rust), Babuk (some derivatives)
- **PE indicators**:
  - `.text` string `Go build ID:`, `runtime.gopclntab`, `runtime.findfunc`, `runtime.epoll_create`
  - Function naming: `main.main`, `runtime.morestack`, `_cgo_runtime_*`
  - Section: `.symtab` w/ Go symbol layout; ELF/PE-specific Go bootstraps (`__rt0_amd64_windows`)
  - PE timestamp often zeroed by Go toolchain (`TimeDateStamp == 0`) — distinct anomaly to flag
- **Evidence: High** (CISA explicitly names Go for BianLian; Trend/Sophos confirm Hive Go pre-rewrite).

### 5.3 .NET DLL with Restart Manager API import cluster (intermittent encryption marker)

- **Families**: Royal, BlackSuit, Conti (later variants), Akira (some samples)
- **PE indicators**:
  - Imports: `rstrtmgr.dll` (RmStartSession, RmRegisterResources, RmGetList, RmEndSession)
  - Plus `IoCreateFile`/`ZwQueryDirectoryFile` from `ntdll.dll`
  - `.text` strings: `intermittent`, `percent`, partial-encrypt CLI flags
- **Why it matters**: Restart Manager is the canonical "find what's holding this file" call. Restart Manager + crypto-API cluster is a tight indicator of intermittent-encryption ransomware. Existing `detect_suspicious_imports` may not have rstrtmgr.dll on the watchlist.
- **Evidence: High** (Cybereason on Royal, CISA on BlackSuit/Royal).

### 5.4 EDRKillShifter / AuKill / Bring-Your-Own-Driver dropper PE shape

- **Families**: RansomHub, BlackCat, BlackBasta, Medusa, BianLian, Play
- **PE indicators**:
  - PE resource of type `RT_RCDATA` carrying an embedded **signed** driver (verify by extracting and parsing the PE-in-PE)
  - Strings: `SCManager`, `\\\\.\\pipe\\`, driver-name strings (`Truesight`, `LDDP`, `RealtekRtcK64`, `gmer64`, `dbutil`, `rentdrv2`, `Process Hacker`, `kprocesshacker`)
  - Imports: `advapi32.dll` (OpenSCManager, CreateService, StartService) + `ntdll.dll` (NtLoadDriver) cluster
  - Optional: `NtTerminateProcess` / `NtClose` (Native API to bypass userland EDR hooks)
- **Note**: existing `byovd` detector watches EVTX EID 7045/4697 with a name allowlist (Zemana cluster). The PE-side gap is: **the dropper that delivers an unknown driver name not in the allowlist** — best caught by the embedded-signed-driver-in-resource pattern.
- **Evidence: High** (Sophos on EDRKillShifter; vendor confirmed RansomHub default tool).

### 5.5 ChaCha20/Salsa20 crypto-library signature (vs. AES-only)

- **Families**: BlackCat (ChaCha20+RSA), Akira (ChaCha20 OR Threefish), Babuk (ChaCha8+SymCrypt), HelloKitty/FiveHands (NTRU+ChaCha20), Hive (ChaCha20)
- **PE indicators**:
  - Constant tables: ChaCha20 "expand 32-byte k" string; Salsa20 sigma string; X25519 P-curve params
  - Imports avoid `advapi32!CryptEncrypt` — they implement the cipher inline
  - Heuristic: presence of 64-byte block of `0x61707865 0x3320646e 0x79622d32 0x6b206574` (ChaCha20 "expand 32-byte k" init constants) is a definitive marker
- **Why it matters**: existing `detect_ransomware_strings` keys on `.wncry/.locked/.enc + bitcoin/onion` — ChaCha20 inline constants catch the **family before any string/extension is observable**. **Evidence: High**.

### 5.6 PE signing — masquerade with stolen/expired/rogue certificates

- **Families**: Rorschach (signed Cortex XDR binary), Five Hands (mhyprot2.sys signed Genshin driver), AtomSilo (BitDefender signed sideload), AvosLocker (varies)
- **PE indicators**:
  - Authenticode chain with: revoked cert serial, expired CN, or CN matches known-stolen-cert list (e.g., `mhyprot2.sys` SHA1 thumbprint `B9F3...`)
  - Subject `CN` mismatch with `OriginalFilename` resource (sideload artifact)
- **Existing**: `detect_zemana_driver_load` covers Zemana by thumbprint; no general rogue-cert detector.
- **Evidence: High** (vendor confirmed for each).

---

## Section 6 — Process termination lists (target processes to watch)

**EID/source**: EID 4688/Sysmon EID 1 `Image` ends `\taskkill.exe` or `\net.exe` or `\sc.exe`. Also Security EID **4689** (process exit) showing mass termination cluster. For `Stop-Service`, PowerShell EID **4104**.

### 6.1 Canonical AV/EDR/security process kill list (intersection of LockBit/Conti/Royal/BlackCat/Phobos/Hive/Akira/RansomHub/BlackBasta/BianLian/Medusa/Rhysida/Play/Babuk/Snatch)

Citation: LockBit 3.0 CISA AA23-075A explicit list; cross-validated against Conti leak source, Babuk leaked source, vendor reports for the others.

```
sql.exe
sqlserv.exe
sqlbrowser.exe
sqlwriter.exe
sqlagent.exe
sqlservr.exe
oracle.exe
ocssd.exe
dbsnmp.exe
synctime.exe
agntsvc.exe
isqlplussvc.exe
xfssvccon.exe
mydesktopservice.exe
mydesktopqos.exe
ocautoupds.exe
encsvc.exe
firefox.exe
tbirdconfig.exe
ocomm.exe
dbeng50.exe
sqbcoreservice.exe
excel.exe
infopath.exe
msaccess.exe
mspub.exe
onenote.exe
outlook.exe
powerpnt.exe
steam.exe
thebat.exe
thunderbird.exe
visio.exe
winword.exe
wordpad.exe
notepad.exe
veeam.exe
veeamguestindexer.exe
veeamtransportsvc.exe
veeamdeploymentsvc.exe
veeammountservice.exe
sophos.exe
SAVAdminService.exe
SAVService.exe
SEDservice.exe
HitmanPro.Alert.exe
GoogleUpdate.exe
mbamtray.exe
mbam.exe
MsMpEng.exe          # Defender (rarely succeeds, but tried)
NisSrv.exe
SecurityHealthService.exe
SentinelAgent.exe
SentinelHelperService.exe
SentinelServiceHost.exe
CSFalconService.exe
CrowdStrike.exe
elastic-agent.exe
ekrn.exe              # ESET
egui.exe
avgnt.exe             # Avira
avguard.exe
avp.exe               # Kaspersky
kavfsslp.exe
klnagent.exe
mfemms.exe            # McAfee
masvc.exe
macmnsvc.exe
mcshield.exe
McAfee*.exe
TmListen.exe          # Trend Micro
PccNTMon.exe
NTRtScan.exe
TmCCSF.exe
ds_agent.exe
backup.exe
BackupExecAgentAccelerator.exe
BackupExecAgentBrowser.exe
BackupExecDeviceMediaService.exe
BackupExecJobEngine.exe
BackupExecManagementService.exe
BackupExecRPCService.exe
BackupExecVSSProvider.exe
bedbg.exe
benetns.exe
beserver.exe
pvlsvr.exe
raw_agent_svc.exe
CagService.exe
Sage.exe
QBW32.exe             # QuickBooks
QBDBMgr.exe
QBDBMgrN.exe
QBCFMonitorService.exe
mysqld.exe
mysqld-nt.exe
mysqld-opt.exe
postgres.exe
PostgreSQL.exe
node.exe              # rare; some target dev servers
java.exe              # rare
Tomcat*.exe
httpd.exe
nginx.exe
zoolz.exe
```

### 6.2 Canonical service stop list (`net stop <svc>` / `sc.exe stop <svc>` / Stop-Service)

```
vss
VSS
SQLServerAgent
MSSQLSERVER
MSSQL$*
SQLBrowser
SQLWriter
ReportServer
ReportServer$*
SQLAgent$*
SQLAnywhere
SQLADHLP
SQLTELEMETRY
Veeam Backup Service
Veeam Backup Catalog Data Service
Veeam Backup CDP Service
Veeam Backup Cloud Gateway Service
Veeam Backup Cloud Gateway
Veeam Backup Indexing
Veeam Backup Manager
Veeam Backup Service Provider
Veeam Backup Transport
Veeam vPower NFS
Veeam Mount Service
Veeam Distribution Service
Veeam DeploymentService
Veeam Installer Service
Veeam Plug-in
VeeamBackupSvc
VeeamCatalogSvc
VeeamCloudSvc
VeeamDeploySvc
VeeamDeploymentService
VeeamDistributionSvc
VeeamEnterpriseManagerSvc
VeeamMountSvc
VeeamNFSSvc
VeeamRESTSvc
VeeamTransportSvc
GxVss               # Commvault
GxBlr
GxFWD
GxCVD
GxCIMgr
BackupExecAgentAccelerator
BackupExecAgentBrowser
BackupExecDeviceMediaService
BackupExecJobEngine
BackupExecManagementService
BackupExecRPCService
BackupExecVSSProvider
AcrSch2Svc          # Acronis
AcronisAgent
ARSM
ASPNET             # IIS app pool stops
BesClient
CASAD2DWebSvc
CCSF
Catalog Server
CIM Object Manager
DCAgent
EhttpSrv
EPSecurityService
EPUpdateService
EraSrv
EsgShKernel
ESHASRV
FA_Scheduler
HealthService
IISADMIN
IMAP4Svc
KAVFS
KAVFSGT
kavfsslp
klnagent
mbamservice
mfefire
mfevtp
McShield
McTaskManager
mfemms
mozyprobackup
MsDtsServer
MsDtsServer100
MsDtsServer110
MMS
MsMpSvc
MSExchangeES
MSExchangeIS
MSExchangeMTA
MSExchangeMGMT
MSExchangeSA
MSExchangeSRS
MSExchangeADTopology
MSExchangeAntispamUpdate
MSExchangeDelivery
MSExchangeDiagnostics
MSExchangeEdgeSync
MSExchangeFastSearch
MSExchangeFrontEndTransport
MSExchangeHM
MSExchangeIMAP4
MSExchangeMailboxAssistants
MSExchangeMailboxReplication
MSExchangePOP3
MSExchangePop3BE
MSExchangeImap4BE
MSExchangeRepl
MSExchangeRPC
MSExchangeServiceHost
MSExchangeThrottling
MSExchangeTransport
MSExchangeTransportLogSearch
MSExchangeUM
MSExchangeUMCR
MSOLAP$SQL_2008
MSSQL$BKUPEXEC
MSSQL$ECWDB2
MSSQL$PRACTICEMGT
MSSQL$PROFXENGAGEMENT
MSSQL$SBSMONITORING
MSSQL$SHAREPOINT
MSSQL$SQL_2008
MSSQL$SYSTEM_BGC
MSSQL$TPS
MSSQL$TPSAMA
MSSQL$VEEAMSQL2008
MSSQL$VEEAMSQL2012
MSSQLFDLauncher
MSSQLServerADHelper
MSSQLServerADHelper100
MSSQLServerOLAPService
NetBackup BMR MTFTP Service
NetMsmqActivator
ntrtscan
OracleClientCache80
PDVFSService
POP3Svc
PortalSvc
QBCFMonitorService
QBVSS
QBIDPService
ReportServer$TPS
ReportServer$TPSAMA
ReportServer$SQL_2008
ReportServer$SYSTEM_BGC
RTVscan
SAVAdminService
SAVService
SDRSVC
SepMasterService
ShMonitor
Smcinst
SmcService
SMTPSvc
SNAC
SntpService
sophos
SophosAgent
SophosAutoUpdateService
SophosClean
SophosDeviceControlService
SophosFIM
SophosHealth
SophosMcsAgent
SophosMcsClient
SophosMessageRouter
SophosNtpService
SophosRms
SophosSafestore
SophosSystemProtectionService
SophosWebControlService
SQLPBDMS
SQLPBENGINE
sqlserveragent
stc_raw_agent
swi_filter
swi_service
swi_update
swi_update_64
TmCCSF
tmlisten
TrueKey
TrueKeyScheduler
TrueKeyServiceHelper
UI0Detect
VeeamBackupSvc
VeeamBrokerSvc
VeeamCatalogSvc
VeeamCloudSvc
VeeamDeploymentService
VeeamDeploySvc
VeeamDistributionSvc
VeeamEnterpriseManagerSvc
VeeamMountSvc
VeeamNFSSvc
VeeamRESTSvc
VeeamTransportSvc
W3Svc
wbengine
WRSVC
YooBackup
YooIT
zhudongfangyu
```

The "GxVss / GxBlr / GxFWD / GxCVD / GxCIMgr" cluster is the Commvault stop-list explicitly published in the LockBit 3.0 CISA advisory (AA23-075A) and is a tight, low-FP cluster.

**Detector proposal — `detect_service_stop_avset`**:
- EID 4688/Sysmon 1 `Image~/net\.exe|sc\.exe$/ ∧ CommandLine~/stop\s+(<SVC>)/i` where `<SVC>` matches the canonical list above, with cluster threshold ≥3 stops in 60s; OR
- PowerShell EID 4104 `ScriptBlockText~/Stop-Service\s+.*<SVC>/i` cluster; OR
- Service Control Manager EID **7036** (state change to Stopped) for ≥3 services in the canonical list within 60s, where the state-change initiator (correlated by Sysmon 1) is a non-`services.exe` interactive parent.
- **FP risk**: Low at cluster threshold. Single stop of any one service can be legitimate; **3+ from the list within 60s is virtually always malicious**.

---

## Section 7 — Methodology and source register

**Sources cited (authoritative)**:

- **CISA #StopRansomware advisories** (cited inline as `[C]` in the matrix): LockBit 3.0 (AA23-075A), Cl0p MOVEit (AA23-158A), Hive (AA22-321A), Vice Society (AA22-249A), Ryuk healthcare (AA20-302A), MedusaLocker (AA22-181A), Phobos (AA24-060A), Daixin (AA22-294A) — referenced as ESXi-via-Babuk-leak comparator, Black Basta (AA24-131A), RansomHub (AA24-242A), BianLian (AA23-136A), Rhysida (AA23-319A), Royal/BlackSuit (AA23-061A), ALPHV/BlackCat (AA23-353A — published as Play title in our fetch but content is ALPHV Blackcat).
- **MITRE ATT&CK**: software pages S0446 (Ryuk), S0521 (BloodHound), S0481 (Ragnar Locker), S0500 (MCMD/DoppelPaymer-adjacent), S0612 (WastedLocker), S0496 (REvil), S0454 (Cobalt Strike), S0575 (Conti), S0366 (WannaCry), S0372 (LockerGoga), S1051 (KEYPLUG/related), S1058 (Prestige), S1068 (BlackCat); group G0102 (Wizard Spider) covering Ryuk/Conti/Diavol heritage.
- **Vendor IR reports**: Sophos (BlackCat, EDRKillShifter, Akira playbook), Microsoft (BlackCat lifetimes blog, DEV-0569 Royal), Cybereason (Royal), Trend Micro (RansomHub EDRKillShifter, Rorschach), Talos (Phobos affiliate, Akira), SentinelLabs (Black Basta), Cynet (Ragnar Locker), Check Point (Rorschach), and the leaked Conti/Babuk source code (publicly mirrored, used for kill-list/process-list ground truth).

**Flags / speculative items** (explicitly hedged):

- The ESXi family list (Section 4) for which "Linux-only" is asserted is based on currently public encryptor variants; some affiliates may have unreleased Windows variants. The "high-confidence Windows-side pivot via SSH/PowerCLI" claim is well-evidenced.
- "Count = ~N/76" estimates are derived from the matrix in Section 1 with hedging band of ±5 because some families' Windows-side TTPs are documented only by single vendors and were not independently corroborated.
- The Rust/Go PE-fingerprint heuristics (Section 5.1–5.2) are reliable for unobfuscated builds; UPX-packed Rust/Go binaries require unpacking first (existing `detect_packed_pe` provides the unpack trigger).
- "Defender disablement via EID 5001" (Section 2.10) requires Defender Operational channel to be retained — many environments do not collect it; falling back to PS-4104 + Sysmon-13 registry is the practical path.

**What is explicitly NOT proposed** (because already covered):
BYOVD with Zemana cluster, HVCI tamper, VSS Application-channel deletion (8193/524), Hyper-V VM shutdown, scheduled task creation (4698/106), QWCrypt PE/process IOCs, WebDAV LOLBin, ransom-note creation (Sysmon-11), WebClient service start, AD Explorer recon, srvcli/netutils sideload, PowerShell history wipe, RPivot/Chisel cmdline, Impacket wmiexec ADMIN$\__, 7-Zip -mhe staging, fake browser-update tasks, workers.dev DNS from non-browser, PE packers, injection-API clusters, AV-exclusion strings, packed PE, anti-debug, hollowing, network IOC strings, persistence strings, ransomware extension strings, credential strings, TLS callbacks, overlay, PE/dotnet anomalies, ransom-note filename PE strings, and the SRUM signals (automated_execution, beaconing, background_cpu_dominant, exfil_signal, suspicious_path, masquerade_candidate, phantom_foreground, notification_c2, selective_gap, qwcrypt_ioc_process).

---

*Document: ransomware-ttp-gap-report.md · Generated 2026-05-30 · Author: Albert Hui (Security Ronin Ltd)*
