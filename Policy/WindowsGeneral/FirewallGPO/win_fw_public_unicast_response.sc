if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109936" );
	script_version( "2019-12-16T11:36:02+0000" );
	script_tag( name: "last_modification", value: "2019-12-16 11:36:02 +0000 (Mon, 16 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-07-03 12:31:16 +0200 (Wed, 03 Jul 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Windows Defender Firewall: Public Profile: Allow unicast response" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_tag( name: "summary", value: "The policy determines whether unicast responses to multicast or
broadcast messages for a public connection will be blocked." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Public Profile: Allow unicast response";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/
Windows Firewall with Advanced Security/Windows Firewall Properties/" + title;
type = "HKLM";
key = "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile";
item = "DisableUnicastResponsesToMulticastBroadcast";
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

