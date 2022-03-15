if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13751" );
	script_version( "2021-03-19T13:48:08+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 13:48:08 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Direct Connect Hub Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/DirectConnectHub", 411 );
	script_xref( name: "URL", value: "http://en.wikipedia.org/wiki/Direct_connect_file-sharing_application" );
	script_tag( name: "summary", value: "Detection of a Direct Connect 'hub' (or server)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 411, proto: "DirectConnectHub" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = recv_line( socket: soc, length: 1024 );
if(!r){
	close( soc );
	exit( 0 );
}
if(ereg( pattern: "^\\$Lock .+", string: r )){
	str = "$quit|";
	send( socket: soc, data: str );
	log_message( port: port );
}
close( soc );
exit( 0 );

