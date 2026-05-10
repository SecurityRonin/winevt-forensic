/// Bundled field-name mappings for the most common Microsoft provider manifests.
///
/// Each entry is `(provider_guid, event_id, field_names_in_order)`.
/// GUIDs are lowercase-with-braces; field names follow the order declared in the
/// provider's `<template>` element (matching `Param1`, `Param2`, … positions).
///
/// Sources: `wevtutil gp <provider> /ge /gm`, Windows SDK manifests, public ETW docs.
pub static ENTRIES: &[(&str, u32, &[&str])] = &[
    // ── Microsoft-Windows-Security-Auditing ──────────────────────────────────
    // {54849625-5478-4994-a5ba-3e3b0328c30d}
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4624, // An account was successfully logged on
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "TargetUserSid",
            "TargetUserName",
            "TargetDomainName",
            "TargetLogonId",
            "LogonType",
            "LogonProcessName",
            "AuthenticationPackageName",
            "WorkstationName",
            "LogonGuid",
            "TransmittedServices",
            "LmPackageName",
            "KeyLength",
            "ProcessId",
            "ProcessName",
            "IpAddress",
            "IpPort",
            "ImpersonationLevel",
            "RestrictedAdminMode",
            "TargetOutboundUserName",
            "TargetOutboundDomainName",
            "VirtualAccount",
            "TargetLinkedLogonId",
            "ElevatedToken",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4625, // An account failed to log on
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "TargetUserSid",
            "TargetUserName",
            "TargetDomainName",
            "Status",
            "FailureReason",
            "SubStatus",
            "LogonType",
            "LogonProcessName",
            "AuthenticationPackageName",
            "WorkstationName",
            "TransmittedServices",
            "LmPackageName",
            "KeyLength",
            "ProcessId",
            "ProcessName",
            "IpAddress",
            "IpPort",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4634, // An account was logged off
        &[
            "TargetUserSid",
            "TargetUserName",
            "TargetDomainName",
            "TargetLogonId",
            "LogonType",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4648, // A logon was attempted using explicit credentials
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "LogonGuid",
            "TargetUserName",
            "TargetDomainName",
            "TargetLogonGuid",
            "TargetServerName",
            "TargetInfo",
            "ProcessId",
            "ProcessName",
            "IpAddress",
            "IpPort",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4656, // A handle to an object was requested
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "ObjectServer",
            "ObjectType",
            "ObjectName",
            "HandleId",
            "TransactionId",
            "AccessList",
            "AccessReason",
            "AccessMask",
            "PrivilegeList",
            "RestrictedSidCount",
            "ProcessId",
            "ProcessName",
            "ResourceAttributes",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4663, // An attempt was made to access an object
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "ObjectServer",
            "ObjectType",
            "ObjectName",
            "HandleId",
            "AccessList",
            "AccessMask",
            "ProcessId",
            "ProcessName",
            "ResourceAttributes",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4672, // Special privileges assigned to new logon
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "PrivilegeList",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4688, // A new process has been created
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "NewProcessId",
            "NewProcessName",
            "TokenElevationType",
            "ProcessId",
            "CommandLine",
            "TargetUserSid",
            "TargetUserName",
            "TargetDomainName",
            "TargetLogonId",
            "ParentProcessName",
            "MandatoryLabel",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4689, // A process has exited
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "Status",
            "ProcessId",
            "ProcessName",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4698, // A scheduled task was created
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "TaskName",
            "TaskContent",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4702, // A scheduled task was updated
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "TaskName",
            "TaskContentNew",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4720, // A user account was created
        &[
            "TargetUserName",
            "TargetDomainName",
            "TargetSid",
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "PrivilegeList",
            "SamAccountName",
            "DisplayName",
            "UserPrincipalName",
            "HomeDirectory",
            "HomePath",
            "ScriptPath",
            "ProfilePath",
            "UserWorkstations",
            "PasswordLastSet",
            "AccountExpires",
            "PrimaryGroupId",
            "AllowedToDelegateTo",
            "OldUacValue",
            "NewUacValue",
            "UserAccountControl",
            "UserParameters",
            "SidHistory",
            "LogonHours",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4732, // A member was added to a security-enabled local group
        &[
            "MemberName",
            "MemberSid",
            "TargetUserName",
            "TargetDomainName",
            "TargetSid",
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "PrivilegeList",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4768, // A Kerberos authentication ticket (TGT) was requested
        &[
            "TargetUserName",
            "TargetDomainName",
            "TargetSid",
            "ServiceName",
            "ServiceSid",
            "TicketOptions",
            "Status",
            "TicketEncryptionType",
            "PreAuthType",
            "IpAddress",
            "IpPort",
            "CertIssuerName",
            "CertSerialNumber",
            "CertThumbprint",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4769, // A Kerberos service ticket was requested
        &[
            "TargetUserName",
            "TargetDomainName",
            "ServiceName",
            "ServiceSid",
            "TicketOptions",
            "TicketEncryptionType",
            "IpAddress",
            "IpPort",
            "Status",
            "LogonGuid",
            "TransmittedServices",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        4776, // The computer attempted to validate the credentials for an account
        &[
            "PackageName",
            "TargetUserName",
            "Workstation",
            "Status",
        ],
    ),
    (
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        1102, // The audit log was cleared
        &[
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
        ],
    ),

    // ── Microsoft-Windows-System-Events / Eventlog ───────────────────────────
    // {fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}  (System log cleared EID 104)
    (
        "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
        104, // The System log file was cleared
        &["SubjectUserName", "SubjectDomainName"],
    ),

    // ── Microsoft-Windows-PowerShell ─────────────────────────────────────────
    // {a0c1853b-5c40-4b15-8766-3cf1c58f985a}
    (
        "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
        4104, // Script block logging
        &[
            "MessageNumber",
            "MessageTotal",
            "ScriptBlockText",
            "ScriptBlockId",
            "Path",
        ],
    ),
    (
        "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
        4103, // Module logging
        &[
            "ContextInfo",
            "UserData",
        ],
    ),

    // ── Microsoft-Windows-WMI-Activity ───────────────────────────────────────
    // {1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}
    (
        "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}",
        5857, // WMI provider loaded
        &[
            "ProviderName",
            "Code",
            "HostProcess",
            "ProviderGUID",
            "IsProvider",
        ],
    ),
    (
        "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}",
        5858, // WMI activity error
        &[
            "NamespaceName",
            "UserName",
            "ClientMachine",
            "ClientMachineFQDN",
            "ClientProcessId",
            "Component",
            "Operation",
            "ResultCode",
            "PossibleCause",
        ],
    ),
    (
        "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}",
        5860, // WMI temporary event subscription
        &[
            "NamespaceName",
            "Query",
            "User",
            "ClientMachine",
        ],
    ),
    (
        "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}",
        5861, // WMI permanent event subscription
        &[
            "NamespaceName",
            "Query",
            "Consumer",
            "PossibleCause",
        ],
    ),

    // ── Microsoft-Windows-Sysmon ─────────────────────────────────────────────
    // {5770385f-c22a-43e0-bf4c-06f5698ffbd9}
    (
        "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        1, // Process Create
        &[
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "FileVersion",
            "Description",
            "Product",
            "Company",
            "OriginalFileName",
            "CommandLine",
            "CurrentDirectory",
            "User",
            "LogonGuid",
            "LogonId",
            "TerminalSessionId",
            "IntegrityLevel",
            "Hashes",
            "ParentProcessGuid",
            "ParentProcessId",
            "ParentImage",
            "ParentCommandLine",
            "ParentUser",
        ],
    ),
    (
        "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        3, // Network connection
        &[
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "User",
            "Protocol",
            "Initiated",
            "SourceIsIpv6",
            "SourceIp",
            "SourceHostname",
            "SourcePort",
            "SourcePortName",
            "DestinationIsIpv6",
            "DestinationIp",
            "DestinationHostname",
            "DestinationPort",
            "DestinationPortName",
        ],
    ),
    (
        "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        7, // Image loaded
        &[
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "ImageLoaded",
            "FileVersion",
            "Description",
            "Product",
            "Company",
            "OriginalFileName",
            "Hashes",
            "Signed",
            "Signature",
            "SignatureStatus",
            "User",
        ],
    ),
    (
        "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        11, // File created
        &[
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "TargetFilename",
            "CreationUtcTime",
            "User",
        ],
    ),

    // ── Microsoft-Windows-TaskScheduler ─────────────────────────────────────
    // {de7b24ea-73c8-4a09-985d-5bdadcfa9017}
    (
        "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}",
        106, // Task registered
        &["TaskName", "UserContext"],
    ),
    (
        "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}",
        200, // Task action launched
        &["TaskName", "TaskInstanceId", "ActionName", "UserContext"],
    ),
    (
        "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}",
        201, // Task action completed
        &["TaskName", "TaskInstanceId", "ActionName", "ResultCode"],
    ),

    // ── Microsoft-Windows-TerminalServices-RemoteConnectionManager ───────────
    // {c76baa63-ae81-421c-b425-340b4b24157f}
    (
        "{c76baa63-ae81-421c-b425-340b4b24157f}",
        1149, // Remote Desktop Services: User authentication succeeded
        &["Param1", "Param2", "Param3"],
    ),

    // ── Microsoft-Windows-Windows Defender ───────────────────────────────────
    // {11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}
    (
        "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
        1116, // Malware detected
        &[
            "Product Name",
            "Product Version",
            "Detection ID",
            "Detection Time",
            "Threat ID",
            "Threat Name",
            "Severity ID",
            "Severity Name",
            "Category ID",
            "Category Name",
            "FWLink",
            "Status Code",
            "Status Description",
            "State",
            "Source ID",
            "Source Name",
            "Process Name",
            "Detection User",
            "Path",
            "Origin ID",
            "Origin Name",
            "Execution ID",
            "Execution Name",
            "Type ID",
            "Type Name",
            "Pre Execution Status",
            "Action ID",
            "Action Name",
            "Remediation User",
            "Error Code",
            "Error Description",
            "Post Clean Status",
            "Additional Actions ID",
            "Additional Actions String",
            "Remediation Type ID",
            "Remediation Type String",
            "Security intelligence Version",
            "Engine Version",
        ],
    ),
];
