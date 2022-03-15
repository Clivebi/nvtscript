if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105009" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-04-09 16:39:22 +0100 (Wed, 09 Apr 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: FTP 'AUTH TLS' Command Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/banner/available" );
	script_tag( name: "summary", value: "Checks if the remote FTP server supports SSL/TLS (FTPS) with the 'AUTH TLS' command." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc4217" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
if(get_port_transport( port ) > ENCAPS_IP){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = ftp_recv_line( socket: soc );
if(!buf){
	ftp_close( socket: soc );
	exit( 0 );
}
buf = ftp_send_cmd( socket: soc, cmd: "AUTH TLS\r\n" );
ftp_close( socket: soc );
if(!buf){
	exit( 0 );
}
if( ContainsString( buf, "234" ) ){
	set_kb_item( name: "ftp/starttls/supported", value: TRUE );
	set_kb_item( name: "ftp/" + port + "/starttls", value: TRUE );
	set_kb_item( name: "starttls_typ/" + port, value: "ftp" );
	log_message( port: port, data: "The remote FTP server supports TLS (FTPS) with the 'AUTH TLS' command." );
}
else {
	set_kb_item( name: "ftp/starttls/not_supported", value: TRUE );
	set_kb_item( name: "ftp/starttls/not_supported/port", value: port );
}
exit( 0 );

