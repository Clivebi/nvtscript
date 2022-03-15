if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14378" );
	script_version( "2021-03-01T08:50:19+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 08:50:19 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NetAsq IPS-Firewall Detection (TCP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 1300 );
	script_xref( name: "URL", value: "http://www.netasq.com" );
	script_tag( name: "summary", value: "TCP (port 1300/tcp) based detection of a NetAsq IPS-Firewall." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = 1300;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "VT-TEST\\r\\n" );
send( socket: soc, data: req );
r = recv( socket: soc, length: 512 );
if(ereg( pattern: "^200 code=[0-9]+ msg=.*", string: r )){
	req = NASLString( "QUIT\\r\\n" );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 512 );
	if(ereg( pattern: "^103 code=[0-9]+ msg=.*\\.\\.\\.", string: r )){
		log_message( port: port );
	}
}
close( soc );
exit( 0 );

