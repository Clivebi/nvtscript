if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140129" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-01-27 09:57:51 +0100 (Fri, 27 Jan 2017)" );
	script_name( "Sybase TCP/IP listener Detection" );
	script_tag( name: "summary", value: "This script detects a Sybase TCP/IP listener server by sending a login packet and checking the response." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "mssql_version.sc", "oracle_tnslsnr_version.sc" );
	script_require_ports( "Services/unknown", 5000 );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("sybase_func.inc.sc");
port = unknownservice_get_port( default: 5000 );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
sql_packet = make_sql_login_pkt( username: "OpenVAS", password: "OpenVAS" );
send( socket: soc, data: sql_packet );
send( socket: soc, data: pkt_lang );
buf = recv( socket: soc, length: 255 );
close( soc );
if(ContainsString( buf, "Login failed" )){
	set_kb_item( name: "sybase/tcp_listener/detected", value: TRUE );
	register_product( cpe: "cpe:/a:sybase:adaptive_server_enterprise", location: port + "/tcp", port: port, service: "sybase_tcp_listener" );
	service_register( proto: "sybase", port: port, message: "Sybase TCP/IP listener is running at this port.\nCPE: cpe:/a:sybase:adaptive_server_enterprise\n" );
	log_message( port: port, data: "Sybase TCP/IP listener is running at this port.\nCPE: cpe:/a:sybase:adaptive_server_enterprise\n" );
	exit( 0 );
}
exit( 0 );

