if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109521" );
	script_version( "2021-02-12T08:47:50+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 08:47:50 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2018-06-28 16:29:29 +0200 (Thu, 28 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows 10: Do not suggest third-party content in Windows spotlight" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 19.7.8.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 19.7.7.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "If you enable this policy, Windows spotlight features like lock
screen spotlight, suggested apps in Start menu or Windows tips will no longer suggest apps and
content from third-party software publishers. Users may still see suggestions and tips to make them
more productive with Microsoft features and apps.

If you disable or do not configure this policy, Windows spotlight features may suggest apps and
content from third-party software publishers in addition to Microsoft apps and content.

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = policy_microsoft_windows_target_string();
title = "Do not suggest third-party content in Windows spotlight";
solution = "Set following UI path accordingly:
User Configuration/Administrative Templates/Windows Components/Cloud Content/" + title;
type = "HKU";
key = "Software\\Policies\\Microsoft\\Windows\\CloudContent";
item = "DisableThirdPartySuggestions";
reg_path = type + "\\[SID]\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( "Value" );
if( !policy_verify_win_ver() ) {
	results = policy_report_wrong_os( target_os: target_os );
}
else {
	if( !sids = registry_hku_subkeys() ) {
		results = policy_report_empty_hku();
	}
	else {
		results = policy_match_exact_dword_profiles( key: key, item: item, default: default, sids: sids );
	}
}
value = results["value"];
comment = results["comment"];
compliant = results["compliant"];
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: reg_path, info: comment );
policy_set_kbs( type: test_type, cmd: reg_path, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

