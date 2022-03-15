if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109572" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-08-16 14:08:29 +0200 (Thu, 16 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows Firewall: Public: Logging: Name" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "%systemroot%\\system32\\logfiles\\firewall\\publicfw.log", id: 1 );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 6.2 Activate audit logging" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 6.3 Enable Detailed Logging" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 6.5 Central Log Management" );
	script_tag( name: "summary", value: "This setting specifies the path and name of the file in which
Windows Firewall will write its log information." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Public Profile: Logging: Name";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/
Windows Firewall with Advanced Security/Windows Firewall Properties/" + title;
type = "HKLM";
key = "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging";
item = "LogFilePath";
reg_path = type + "\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( name: "Value", id: 1 );
if( !policy_verify_win_ver( min_ver: win_min_ver ) ) {
	results = policy_report_wrong_os( target_os: target_os );
}
else {
	results = policy_match_reg_sz( key: key, item: item, type: type, default: default, partial: FALSE, multi_sz: FALSE );
}
value = results["value"];
comment = results["comment"];
compliant = results["compliant"];
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: reg_path, info: comment );
policy_set_kbs( type: test_type, cmd: reg_path, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

