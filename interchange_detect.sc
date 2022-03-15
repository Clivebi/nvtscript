if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11128" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 5453 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "redhat Interchange" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/www", 7786 );
	script_tag( name: "solution", value: "Upgrade your software if necessary or configure it
  for 'Unix mode' communication only." );
	script_tag( name: "summary", value: "It seems that 'Red Hat Interchange' ecommerce and dynamic
  content management application is running in 'Inet' mode on this port." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 7786 );
host = http_host_name( port: port );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: NASLString( "VTTEST / HTTP/1.0", "\\r\\n", "Host: ", host, "\\r\\n\\r\\n" ) );
r = recv( socket: soc, length: 1024 );
close( soc );
if(ContainsString( r, "/ not a Interchange catalog or help file" )){
	log_message( port );
}

