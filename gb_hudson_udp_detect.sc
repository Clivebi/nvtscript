if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142613" );
	script_version( "2020-11-09T11:11:32+0000" );
	script_tag( name: "last_modification", value: "2020-11-09 11:11:32 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-07-18 06:44:09 +0000 (Thu, 18 Jul 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Hudson CI Detection (Auto Discovery)" );
	script_tag( name: "summary", value: "The scripts tries to detect a Auto Discovery service of a Hudson CI
  server and to extract a possible exposed version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_open_udp_ports.sc" );
	script_require_udp_ports( "Services/udp/unknown", 33848 );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 33848, ipproto: "udp" );
if(!soc = open_sock_udp( port )){
	exit( 0 );
}
send( socket: soc, data: "\\n" );
recv = recv( socket: soc, length: 512 );
close( soc );
if(!recv || !ContainsString( recv, "<hudson><" ) || ContainsString( recv, "<server-id>" )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "hudson/detected", value: TRUE );
set_kb_item( name: "hudson/autodiscovery/detected", value: TRUE );
set_kb_item( name: "hudson/autodiscovery/port", value: port );
vers = eregmatch( pattern: "<version>([0-9.]+)</version>", string: recv );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "hudson/autodiscovery/" + port + "/version", value: version );
set_kb_item( name: "hudson/autodiscovery/" + port + "/concluded", value: recv );
exit( 0 );

