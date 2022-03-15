if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.116000" );
	script_version( "2020-10-13T11:16:11+0000" );
	script_tag( name: "last_modification", value: "2020-10-13 11:16:11 +0000 (Tue, 13 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-13 07:09:27 +0000 (Tue, 13 Oct 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Service: Microsoft Store Install Service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "4;0;1;2;3" );
	script_xref( name: "URL", value: "http://revertservice.com/10/installservice/" );
	script_tag( name: "summary", value: "This service provides support for the Microsoft Store." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = policy_microsoft_windows_target_string();
title = "Microsoft Store Install Service";
solution = "Set following UI path accordingly:
Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\" + title;
type = "HKLM";
key = "SYSTEM\\CurrentControlSet\\Services\\InstallService";
item = "Start";
cmd = type + "\\" + key + "!" + item;
test_type = "RegKey";
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
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

