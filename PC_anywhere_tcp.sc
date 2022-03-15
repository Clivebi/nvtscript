if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10794" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "pcAnywhere TCP" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Alert4Web.com" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 65301, 5631 );
	script_tag( name: "summary", value: "pcAnywhere is running on this port." );
	script_tag( name: "solution", value: "Disable this service if you do not use it." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
for port in make_list( 65301,
	 5631 ) {
	if(!service_is_unknown( port: port )){
		continue;
	}
	if(!get_port_state( port )){
		continue;
	}
	if(!soc = open_sock_tcp( port )){
		continue;
	}
	send( socket: soc, data: raw_string( 0, 0, 0, 0 ) );
	r = recv( socket: soc, length: 36 );
	close( soc );
	if(r && ContainsString( r, "Please press <" )){
		service_register( port: port, proto: "pcanywheredata" );
		log_message( port: port );
	}
}
exit( 0 );

