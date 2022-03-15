if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100479" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Ingres Database Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 21071 );
	script_tag( name: "summary", value: "This host is running Ingres Database. Ingres Database is an open source
database management system." );
	script_xref( name: "URL", value: "http://www.ingres.com/products/ingres-database.php" );
	exit( 0 );
}
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("port_service_func.inc.sc");
port = "21071";
if(!get_tcp_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
req = raw_string( 0x23, 0x00, 0x4a, 0x43, 0x54, 0x4c, 0x43, 0x52, 0x01, 0x01, 0x02, 0x02, 0x01, 0x0f, 0x06, 0x04, 0x44, 0x4d, 0x4d, 0x4c, 0x03, 0x0d, 0x01, 0x01, 0x06, 0x03, 0x08, 0xb8, 0x97, 0xc4, 0xdf, 0x07, 0x89, 0xe3, 0xf1 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 256 );
if(strlen( buf ) && getword( blob: buf, pos: 0 ) == strlen( buf ) && ContainsString( buf, "DMML" )){
	service_register( port: port, ipproto: "tcp", proto: "iigcd" );
	log_message( port: port );
	exit( 0 );
}
exit( 0 );

