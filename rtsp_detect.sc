if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10762" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "RTSP Server type and version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Alert4Web.com" );
	script_family( "Service detection" );
	script_dependencies( "find_service5.sc" );
	script_require_ports( "Services/rtsp", 554 );
	script_tag( name: "summary", value: "This detects the RTSP Server's type and version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("sip.inc.sc");
port = service_get_port( default: 554, proto: "rtsp" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
data = NASLString( "OPTIONS * RTSP/1.0\\r\\n\\r\\n" );
send( socket: soc, data: data );
header = recv( socket: soc, length: 1024 );
close( soc );
if( IsMatchRegexp( header, "^RTSP/1\\.[0-9]+ " ) && ( ContainsString( header, "CSeq: " ) || ContainsString( header, "Public: " ) || ContainsString( header, "Server: " ) ) ){
	found = TRUE;
}
else {
	soc = open_sock_tcp( port );
	if(soc){
		data = sip_construct_options_req( port: port, proto: "tcp" );
		send( socket: soc, data: data );
		header = recv( socket: soc, length: 1024 );
		close( soc );
		if(IsMatchRegexp( header, "^RTSP/1\\.[0-9]+ " ) && ( ContainsString( header, "CSeq: " ) || ContainsString( header, "Public: " ) || ContainsString( header, "Server: " ) )){
			found = TRUE;
		}
	}
}
if(found){
	service_register( proto: "rtsp", port: port );
	server = egrep( pattern: "Server:", string: header, icase: TRUE );
	auth = egrep( pattern: "WWW-Authenticate:", string: header, icase: TRUE );
	if(server){
		server = chomp( server );
		set_kb_item( name: "RTSP/server_banner/available", value: TRUE );
		set_kb_item( name: "RTSP/server_or_auth_banner/available", value: TRUE );
		set_kb_item( name: "RTSP/" + port + "/server_banner", value: server );
		report = NASLString( "The remote RTSP server is :\\n\\n", server, "\\n\\n" );
	}
	if(auth){
		auth = chomp( auth );
		set_kb_item( name: "RTSP/auth_banner/available", value: TRUE );
		set_kb_item( name: "RTSP/server_or_auth_banner/available", value: TRUE );
		set_kb_item( name: "RTSP/" + port + "/auth_banner", value: auth );
	}
	report += NASLString( "All RTSP Header for 'OPTIONS *' method:\\n\\n", chomp( header ) );
	log_message( port: port, data: report );
}
exit( 0 );

