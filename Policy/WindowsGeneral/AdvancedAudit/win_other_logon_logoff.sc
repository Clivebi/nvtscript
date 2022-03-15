if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109588" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-08-20 10:10:59 +0200 (Mon, 20 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Audit Other Logon/Logoff Events" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "win_AdvancedPolicySettings.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "Success and Failure;Success;Failure;No Auditing" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 6.3 Enable Detailed Logging" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16.13 Alert on Account Login Behavior Deviation" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16.16 Maintain an Inventory of Accounts" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-logonlogoff-events" );
	script_tag( name: "summary", value: "Audit Other Logon/Logoff Events determines whether Windows
generates audit events for other logon or logoff events.

These other logon or logoff events include:

  - A Remote Desktop session connects or disconnects.

  - A workstation is locked or unlocked.

  - A screen saver is invoked or dismissed.

  - A replay attack is detected. This event indicates that a Kerberos request was received twice with
identical information. This condition could also be caused by network misconfiguration.

  - A user is granted access to a wireless network. It can be either a user account or the computer
account.

  - A user is granted access to a wired 802.1x network. It can be either a user account or the
computer account.

Logon events are essential to understanding user activity and detecting potential attacks.

(C) Microsoft Corporation 2017." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Audit Other Logon/Logoff Events";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit
Policies/Logon / Logoff/" + title;
key = "WMI/AdvancedPolicy/OtherLogonLogoffEvents";
test = "auditpol /get /category:*";
test_type = "WMI_Query";
default = script_get_preference( "Value" );
if( !policy_verify_win_ver( min_ver: win_min_ver ) ){
	results = policy_report_wrong_os( target_os: target_os );
}
else {
	results = policy_win_get_advanced_audit_results( key: key, default: default );
}
value = results["value"];
comment = results["comment"];
compliant = results["compliant"];
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: test, info: comment );
policy_set_kbs( type: test_type, cmd: test, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

