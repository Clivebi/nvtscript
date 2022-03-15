if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109245" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-12 14:47:04 +0200 (Tue, 12 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: User Account Control: Detect application installations and prompt for elevation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 2.6 Address unapproved software" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 2.7 Utilize Application Whitelisting" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-detect-application-installations-and-prompt-for-elevation" );
	script_tag( name: "summary", value: "This policy setting determines the behavior of application
installation detection for the entire system. Some software might attempt to install itself after
being given permission to run. The user may give permission for the program to run because the
program is trusted. Then the user is prompted to install an unknown component. This security policy
provides another way to identify and stop these attempted software installations before they can do
damage.

(C) Microsoft Corporation 2017." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "User Account Control: Detect application installations and prompt for elevation";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
item = "EnableInstallerDetection";
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

