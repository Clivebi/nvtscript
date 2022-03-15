if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109570" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-08-16 14:08:29 +0200 (Thu, 16 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows Firewall: Public: Outbound connections" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "0;1" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 9.4 Apply Host-based Firewalls or Port Filtering" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 11.2 Document Traffic Configuration Rules" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 11.3 Use Automated Tools to Verify Standard Device Configurations and Detect Changes" );
	script_tag( name: "summary", value: "This setting determines the behavior for outbound connections
that do not match an outbound firewall rule." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Public Profile: Outbound connections";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/
Windows Firewall with Advanced Security/Windows Firewall Properties/" + title;
type = "HKLM";
key = "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile";
item = "DefaultOutboundAction";
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

