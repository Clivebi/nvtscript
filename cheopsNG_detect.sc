if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20160" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Cheops NG Agent Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "find_service2.sc" );
	script_require_ports( "Services/unknown", 2300 );
	script_xref( name: "URL", value: "http://cheops-ng.sourceforge.net/" );
	script_tag( name: "summary", value: "The remote host is running a network management tool.

Description :

The remote host is running a Cheops NG agent.  Cheops NG is an
open-source network management tool, and the cheops-agent provides a
way for remote hosts to communicate with the tool and use it to map
your network, port scan machines and identify running services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
m1 = "\x00\x00\x00\x14\x00\x0c\x00\x04\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00";
m2 = "\x00\x00\x00\x20\x00\x0c\x00\x02\x00\x00\x00\x00\x01\x00\x00\x7f\x01\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\xb8\xdf\x0d\x08";
port = unknownservice_get_port( default: 2300 );
soc = open_sock_tcp( port );
if(soc){
	send( socket: soc, data: m1 );
	r = recv( socket: soc, length: 512 );
	if(strlen( r ) > 0){
		if(substr( r, 0, 7 ) == "\x00\x00\x00\x10\x00\x0c\x00\x6c"){
			log_message( port: port );
			service_register( port: port, proto: "cheops-ng" );
			set_kb_item( name: "cheopsNG/password", value: port );
		}
		close( soc );
		exit( 0 );
	}
	send( socket: soc, data: m2 );
	r = recv( socket: soc, length: 512 );
	l = strlen( r );
	if(l >= 8 && substr( r, 0, 2 ) == "\0\0\0" && ContainsString( r, "\x01\x00\x00\x7f" )){
		log_message( port: port );
		service_register( port: port, proto: "cheops-ng" );
		set_kb_item( name: "cheopsNG/unprotected", value: port );
	}
	close( soc );
}
exit( 0 );

