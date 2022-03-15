if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109170" );
	script_version( "2020-12-10T10:38:57+0000" );
	script_tag( name: "last_modification", value: "2020-12-10 10:38:57 +0000 (Thu, 10 Dec 2020)" );
	script_tag( name: "creation_date", value: "2018-05-23 15:17:18 +0200 (Wed, 23 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows Defender AV: Turn off Windows Defender Antivirus" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "0;1" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting turns off Windows Defender Antivirus.

If you enable this policy setting, Windows Defender Antivirus does not run, and computers are not
scanned for malware or other potentially unwanted software.

If you disable or do not configure this policy setting, by default Windows Defender Antivirus runs
and computers are scanned for malware and other potentially unwanted software.

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 8.1 or later";
win_min_ver = "6.3";
title = "Turn off Windows Defender Antivirus";
solution = "Set following UI path accordingly: Windows Components/Windows Defender Antivirus/" + title;
type = "HKLM";
key = "Software\\Policies\\Microsoft\\Windows Defender";
item = "DisableAntiSpyware";
reg_path = type + "\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( "Value" );
if( !policy_verify_win_ver( min_ver: win_min_ver ) ) {
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

