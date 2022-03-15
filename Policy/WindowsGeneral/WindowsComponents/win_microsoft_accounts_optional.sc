if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109368" );
	script_version( "2021-02-08T13:58:16+0000" );
	script_tag( name: "last_modification", value: "2021-02-08 13:58:16 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2018-06-25 12:18:07 +0200 (Mon, 25 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Allow Microsoft accounts to be optional" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16.2 Configure Centralized Point of Authentication" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting lets you control whether Microsoft accounts
are optional for Windows Store apps that require an account to sign in. This policy only affects
Windows Store apps that support it.

If you enable this policy setting, Windows Store apps that typically require a Microsoft account to
sign in will allow users to sign in with an enterprise account instead.

If you disable or do not configure this policy setting, users will need to sign in with a Microsoft
account.

(C) 2015 Microsoft Corporation." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 8.1 or later";
win_min_ver = "6.3";
title = "Allow Microsoft accounts to be optional";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/App runtime/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
item = "MSAOptional";
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

