if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114080" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-03-08 13:36:06 +0100 (Fri, 08 Mar 2019)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "NetLinx Controller Unprotected Telnet Access" );
	script_dependencies( "gb_netlinx_telnet_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "netlinx/telnet/unprotected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The NetLinx Controller is accessible via an unprotected telnet connection." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to configure and control the device." );
	script_tag( name: "solution", value: "Disable the telnet access or protect it via a strong password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
CPE = "cpe:/h:amx:netlinx_controller";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(get_kb_item( "netlinx/telnet/" + port + "/unprotected" )){
	report = "The Telnet access of this NetLinx Controller on port " + port + " is unprotected.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

