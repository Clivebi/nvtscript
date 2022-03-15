if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109467" );
	script_version( "2019-12-13T11:11:18+0000" );
	script_tag( name: "last_modification", value: "2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-06-27 11:31:47 +0200 (Wed, 27 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: LPT port redirection (Remote Desktop Services)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting specifies whether to prevent the redirection
of data to client LPT ports during a Remote Desktop Services session.

You can use this setting to prevent users from mapping local LPT ports and redirecting data from the
remote computer to local LPT port peripherals. By default, Remote Desktop Services allows LPT port
redirection.

If you enable this policy setting, users in a Remote Desktop Services session cannot redirect server
data to the local LPT port.

If you disable this policy setting, LPT port redirection is always allowed.

If you do not configure this policy setting, LPT port redirection is not specified at the Group
Policy level.

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Do not allow LPT port redirection";
solution = "Set following UI path accordingly:
Windows Components/Remote Desktop Services/Remote Desktop Session Host/Device and Resource Redirection/" + title;
type = "HKLM";
key = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services";
item = "fDisableLPT";
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

