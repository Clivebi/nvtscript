if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103665" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Moxa NPort Unprotected Telnet Console" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-19 12:36:40 +0100 (Tue, 19 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "General" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "solution", value: "Set a password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "summary", value: "The remote Moxa NPort Telnet Console is not protected by a password." );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Basic settings" ) || !ContainsString( banner, "Change password" ) || !ContainsString( banner, "Load factory default" )){
	exit( 0 );
}
security_message( port: port );
exit( 0 );

