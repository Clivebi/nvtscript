if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96047" );
	script_version( "2019-11-12T12:38:46+0000" );
	script_tag( name: "last_modification", value: "2019-11-12 12:38:46 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2010-01-15 16:20:21 +0100 (Fri, 15 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Last Access Timestamp'" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "0;1" );
	script_tag( name: "summary", value: "Read the status of NTFS MAC 'Last Access Timestamp'." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = policy_microsoft_windows_target_string();
title = "Last Access Timestamp";
solution = "Run following command in elevated command prompt: 'fsutil behavior set disablelastaccess [0,1]'";
type = "HKLM";
key = "SYSTEM\\CurrentControlSet\\Control\\FileSystem";
item = "NtfsDisableLastAccessUpdate";
reg_path = type + "\\" + key + "!" + item;
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
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: reg_path, info: comment );
policy_set_kbs( type: test_type, cmd: reg_path, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

