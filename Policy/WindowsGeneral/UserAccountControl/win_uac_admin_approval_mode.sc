if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109241" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-12 14:31:04 +0200 (Tue, 12 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: User Account Control: Admin Approval Mode for the Built-in Administrator account" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 4.4 Use Unique Passwords" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-admin-approval-mode-for-the-built-in-administrator-account" );
	script_tag( name: "summary", value: "This policy setting determines the behavior of Admin Approval
Mode for the built-in administrator account. When the Admin Approval Mode is enabled, the local
administrator account functions like a standard user account, but it has the ability to elevate
privileges without logging on by using a different account. In this mode, any operation that
requires elevation of privilege displays a prompt that allows the administrator to permit or deny
the elevation of privilege. If Admin Approval Mode is not enabled, the built-in Administrator
account runs all applications by default with full administrative privileges. By default, Admin
Approval Mode is set to Disabled.

(C) Microsoft Corporation 2017." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "User Account Control: Admin Approval Mode for the Built-in Administrator account";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
item = "FilterAdministratorToken";
reg_path = type + "\\" + key + "!" + item;
default = script_get_preference( "Value" );
if( !policy_verify_win_ver( min_ver: win_min_ver ) ){
	results = policy_report_wrong_os( target_os: target_os );
}
else {
	results = policy_match_exact_reg_dword( key: key, item: item, type: type, default: default );
}
value = results["value"];
comment = results["comment"];
compliant = results["compliant"];
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: reg_path, info: comment );
policy_set_kbs( type: test_type, cmd: reg_path, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

