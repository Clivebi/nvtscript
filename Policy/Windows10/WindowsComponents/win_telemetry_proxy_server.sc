if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109610" );
	script_version( "2019-12-13T11:11:18+0000" );
	script_tag( name: "last_modification", value: "2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-09-14 12:00:44 +0200 (Fri, 14 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Configure Connected User Experiences and Telemetry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Proxy", type: "entry", value: "None" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "With this policy setting, you can forward Connected User
Experience and Telemetry requests to a proxy server.

If you enable this policy setting, you can specify the FQDN or IP address of the destination device
within your organization's network (and optionally a port number, if desired). The connection will
be made over a Secure Sockets Layer (SSL) connection.

If the named proxy fails, or if you disable or do not configure this policy setting, Connected User
Experience and Telemetry data will be sent to Microsoft using the default proxy configuration.

The format for this setting is <server>:<port>

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = policy_microsoft_windows_target_string();
title = "Configure Connected User Experiences and Telemetry";
solution = "Set following UI path accordingly: Windows Components/Data Collection and Preview Builds/" + title;
type = "HKLM";
key = "Software\\Policies\\Microsoft\\Windows\\DataCollection";
item = "TelemetryProxyServer";
reg_path = type + "\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( "Proxy" );
if( !policy_verify_win_ver() ) {
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

