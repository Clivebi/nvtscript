if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108071" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "creation_date", value: "2017-02-06 11:18:02 +0100 (Mon, 06 Feb 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: MySQL / MariaDB (STARTTLS-like) SSL/TLS Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL_MariaDB/installed" );
	script_tag( name: "summary", value: "Checks if the remote MySQL / MariaDB server supports (STARTTLS-like) SSL/TLS." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://dev.mysql.com/doc/internals/en/ssl.html" );
	exit( 0 );
}
require("mysql.inc.sc");
require("ssl_funcs.inc.sc");
require("byte_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
req = raw_string( 0x20, 0x00, 0x00, 0x01, 0x05, 0xae, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
port = service_get_port( default: 3306, proto: "mysql" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = mysql_recv_server_handshake( socket: soc );
send( socket: soc, data: req );
hello = ssl_hello( port: port );
send( socket: soc, data: hello );
hello_done = FALSE;
for(;!hello_done;){
	buf = ssl_recv( socket: soc );
	if(!buf){
		close( soc );
		exit( 0 );
	}
	record = search_ssl_record( data: buf, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
	if(record){
		hello_done = TRUE;
		break;
	}
}
close( soc );
if(hello_done){
	set_kb_item( name: "mysql/" + port + "/starttls", value: TRUE );
	set_kb_item( name: "starttls_typ/" + port, value: "mysql" );
	log_message( port: port, data: "The remote MySQL / MariaDB server supports (STARTTLS-like) SSL/TLS." );
}
exit( 0 );

