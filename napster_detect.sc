if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10344" );
	script_version( "2021-04-15T08:31:15+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 08:31:15 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Napster Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Beyond Security" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 6699 );
	script_tag( name: "summary", value: "Detection of Napster." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = 6699;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
res = recv( socket: soc, length: 50 );
if(res && ContainsString( res, "1" )){
	data = NASLString( "GET\\r\\n" );
	send( socket: soc, data: data );
	res = recv( socket: soc, length: 50 );
	if(!res){
		data = NASLString( "GET /\\r\\n" );
		send( socket: soc, data: data );
		res = recv( socket: soc, length: 150 );
		if(ContainsString( res, "FILE NOT SHARED" )){
			report = "Napster was detected on the target system.";
			log_message( data: report, port: port );
			service_register( proto: "napster", port: port );
		}
	}
}
close( soc );
exit( 0 );

