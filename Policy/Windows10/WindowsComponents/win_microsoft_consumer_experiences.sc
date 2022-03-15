if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109430" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-26 13:57:38 +0200 (Tue, 26 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows 10: Turn off Microsoft consumer experiences" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 13.3 Monitor and Block Unauthorized Network Traffic" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting turns off experiences that help consumers
make the most of their devices and Microsoft account.

If you enable this policy setting, users will no longer see personalized recommendations from
Microsoft and notifications about their Microsoft account.

If you disable or do not configure this policy setting, users may see suggestions from Microsoft and
notifications about their Microsoft account.

Note: This setting only applies to Enterprise and Education SKUs.

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
target_os = policy_microsoft_windows_target_string();
title = "Turn off Microsoft consumer experiences";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/Camera/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\\Policies\\Microsoft\\Windows\\CloudContent";
item = "DisableWindowsConsumerFeatures";
reg_path = type + "\\" + key + "!" + item;
default = script_get_preference( "Value" );
if( !policy_verify_win_ver() ) {
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

