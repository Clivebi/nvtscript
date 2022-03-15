if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102017" );
	script_version( "2021-04-16T08:08:22+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 08:08:22 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-02 10:10:27 +0200 (Fri, 02 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "CA ARCServe Backup Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 1900 );
	script_xref( name: "URL", value: "http://arcserve.com/us/products/product.aspx?id=5282" );
	script_tag( name: "summary", value: "Detection of CA ARCServe Backup for Laptops and Desktops." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = 1900;
if(!get_port_state( port )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
senddata = NASLString( "0000000019rxrGetServerVersion\\n" );
send( socket: soc, data: senddata );
r = recv_line( socket: soc, length: 1000 );
match = eregmatch( pattern: "[0-9]+\\.[0-9]+\\.[0-9]+", string: r );
if(match){
	set_kb_item( name: NASLString( "arcserve/", port, "/version" ), value: match[0] );
	set_kb_item( name: "arcserve/installed", value: TRUE );
	info = "CA ARCServe Backup for Laptops and Desktops r" + match[0];
	info = "\n" + "The following version of CA ARCServe Backup for Laptops and Desktops is detected: " + "\n\n" + info;
	log_message( port: port, data: info );
}
close( soc );
exit( 0 );

