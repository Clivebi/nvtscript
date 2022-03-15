if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11865" );
	script_version( "2021-04-16T08:08:22+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 08:08:22 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SOCKS Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_require_ports( "Services/socks4", "Services/socks5", "Services/unknown", 1080 );
	script_dependencies( "find_service.sc", "find_service2.sc" );
	script_tag( name: "summary", value: "A SOCKS server is running on this host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
func mark_socks_proxy( port, ver, ext_ip, authm ){
	var rep;
	service_register( port: port, proto: "socks" + ver );
	rep = strcat( "A SOCKS", ver, " server is running on this port\n" );
	if( ext_ip ){
		rep = strcat( rep, "Its external interface address is ", ext_ip, "\n" );
	}
	else {
		rep = strcat( rep, "We could not determine its external interface address\n" );
	}
	if(!isnull( authm )){
		set_kb_item( name: "socks" + ver + "/auth/" + port, value: authm );
		if( authm == 0 ) {
			rep = strcat( rep, "It does not require authentication, or does not implement it.\n" );
		}
		else {
			if( authm == 1 ) {
				rep = strcat( rep, "It prefers the username/password authentication.\n" );
			}
			else {
				if( authm == 2 ) {
					rep = strcat( rep, "It prefers the GSS API authentication.\n" );
				}
				else {
					if( authm == 255 ) {
						rep = strcat( rep, "It rejected all standard authentication methods (none, password, GSS API).\n" );
					}
					else {
						rep = strcat( rep, "It prefers the unknown ", authm, " authentication method (bug?)\n" );
					}
				}
			}
		}
	}
	log_message( port: port, data: rep );
}
func test_socks( port ){
	soc = open_sock_tcp( port );
	if(!soc){
		return;
	}
	req4 = raw_string( 4, 2, 255, 255, 10, 10, 10, 10 );
	req4 += "root";
	req4 += raw_string( 0 );
	send( socket: soc, data: req4 );
	data = recv( socket: soc, length: 8 );
	close( soc );
	if(strlen( data ) == 8){
		if(ord( data[0] ) == 0 && ord( data[1] ) >= 90 && ord( data[1] ) <= 93){
			if( ord( data[1] ) == 90 ){
				ext = strcat( ord( data[4] ), ".", ord( data[5] ), ".", ord( data[6] ), ".", ord( data[7] ) );
			}
			else {
				exp = NULL;
			}
			set_kb_item( name: "socks4/detected", value: TRUE );
			mark_socks_proxy( port: port, ver: 4, ext_ip: ext );
		}
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return;
	}
	req5 = raw_string( 5, 3, 0, 1, 2 );
	send( socket: soc, data: req5 );
	data = recv( socket: soc, length: 2 );
	if(strlen( data ) == 2){
		if(ord( data[0] ) == 5 && ( ord( data[1] ) <= 2 || ord( data[1] == 255 ) )){
			authm = ord( data[1] );
			req5 = raw_string( 5, 2, 0, 1, 10, 10, 10, 10, 255, 255 );
			send( socket: soc, data: req5 );
			data = recv( socket: soc, length: 10 );
			if( strlen( data ) < 4 || ord( data[1] ) != 0 || ord( data[3] ) != 1 ){
				ext = NULL;
			}
			else {
				ext = strcat( ord( data[4] ), ".", ord( data[5] ), ".", ord( data[6] ), ".", ord( data[7] ) );
			}
			set_kb_item( name: "socks5/detected", value: TRUE );
			mark_socks_proxy( port: port, ver: 5, ext_ip: ext, authm: authm );
		}
	}
	close( soc );
}
s = service_get_ports( proto: "socks4" );
if( !isnull( s ) ) {
	s = make_list( s );
}
else {
	s = make_list();
}
s2 = service_get_ports( proto: "socks5" );
if( !isnull( s2 ) ) {
	s2 = make_list( s2 );
}
else {
	s2 = make_list();
}
s3 = unknownservice_get_ports( default_port_list: make_list( 1080 ) );
if( !isnull( s3 ) ) {
	s3 = make_list( s3 );
}
else {
	s3 = make_list();
}
ports = nasl_make_list_unique( 1080, s, s2, s3 );
for port in ports {
	if(get_port_state( port ) && service_is_unknown( port: port )){
		test_socks( port: port );
	}
}
exit( 0 );

