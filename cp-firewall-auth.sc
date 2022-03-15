if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10675" );
	script_version( "2021-01-20T14:57:47+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 14:57:47 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "CheckPoint Firewall-1 Telnet Authentication Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( 259 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "summary", value: "A Firewall-1 Client Authentication Server is running on this port." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
port = 259;
if(!get_port_state( port )){
	exit( 0 );
}
data = telnet_get_banner( port: port );
if(data && ContainsString( data, "Check Point FireWall-1 Client Authentication Server running on" )){
	log_message( port: port );
}
exit( 0 );

