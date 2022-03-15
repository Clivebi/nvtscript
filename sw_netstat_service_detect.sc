if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113758" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-11-06 18:00:00 +0100 (Fri, 06 Nov 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "netstat Service Detection" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/netstat", 15 );
	script_tag( name: "summary", value: "The script checks the presence of a netstat service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( proto: "netstat", default: 15 );
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "TEST\\r\\n\\r\\n" );
buf = recv( socket: soc, length: 64 );
close( soc );
if(ContainsString( buf, "Active Internet connections" ) || ContainsString( buf, "Active connections" ) || ( ContainsString( buf, "ESTABLISHED" ) && ContainsString( buf, "TCP" ) )){
	service_register( port: port, proto: "netstat" );
	set_kb_item( name: "netstat/installed", value: TRUE );
	set_kb_item( name: "netstat/port", value: port );
	set_kb_item( name: "netstat/" + port + "/installed", value: TRUE );
	report = "The netstart service was detected on the target host.";
	log_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

