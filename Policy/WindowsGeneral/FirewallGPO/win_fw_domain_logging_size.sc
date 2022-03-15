if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109557" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-08-16 14:08:29 +0200 (Thu, 16 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows Firewall: Domain: Logging: Size limit (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Minimum", type: "entry", value: "16384" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 9.1.6  (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16384 KB or greater'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16384 KB or greater'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 6.4 Ensure adequate storage for logs" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 6.5 Central Log Management" );
	script_tag( name: "summary", value: "This setting specifies the size limit of the file in which
Windows Firewall will write its log information." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Windows Defender Firewall: Allow logging";
solution = "Set following UI path accordingly:
Network/Network Connections/Windows Defender Firewall/Domain Profile/" + title;
type = "HKLM";
key = "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging";
item = "LogFileSize";
reg_path = type + "\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( "Minimum" );
if( !policy_verify_win_ver( min_ver: win_min_ver ) ) {
	results = policy_report_wrong_os( target_os: target_os );
}
else {
	results = policy_min_max_reg_dword( key: key, item: item, type: type, default: default, min: TRUE, max: FALSE, not_zero: FALSE, as_sz: FALSE );
}
value = results["value"];
comment = results["comment"];
compliant = results["compliant"];
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: reg_path, info: comment );
policy_set_kbs( type: test_type, cmd: reg_path, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );
