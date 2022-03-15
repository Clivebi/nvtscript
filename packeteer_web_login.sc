if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80032" );
	script_version( "2021-03-19T09:23:16+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 09:23:16 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Packeteer Web Management Interface Login (HTTP)" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 nnposter" );
	script_dependencies( "logins.sc", "packeteer_web_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "bluecoat_packetshaper/installed", "http/password" );
	script_tag( name: "summary", value: "It is possible to log onto the remote web application.

  The scanner was able to log onto the remote Packeteer web management
  interface with the given credentials and has stored the authentication
  cookie in the KB for use with other plugins." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
if(!get_kb_item( "bluecoat_packetshaper/installed" )){
	exit( 0 );
}
if(!get_kb_item( "http/password" )){
	exit( 0 );
}
func hex2str(  ){
	var xlat, hs, s, i, j;
	hs = _FCT_ANON_ARGS[0];
	s = "";
	for(i = 0;i < 256;++i){
		xlat[substr( hex( i ), 2 )] = raw_string( i );
	}
	for(j = 0;j < strlen( hs ) / 2;++j){
		s += xlat[substr( hs, 2 * j, 2 * j + 1 )];
	}
	return s;
}
port = http_get_port( default: 80 );
if(!get_kb_item( "www/" + port + "/packeteer" )){
	exit( 0 );
}
resp = http_send_recv( port: port, data: http_get( item: "/login.htm", port: port ) );
if(!resp){
	exit( 0 );
}
match = eregmatch( pattern: "challenge *= *\"([0-9A-Fa-f]{32})\".{1,80}chapID *= *\"([0-9]*)\"", string: resp );
challenge = match[1];
chapid = match[2];
if(!challenge || !chapid){
	exit( 0 );
}
authsrc = raw_string( int( chapid ) ) + get_kb_item( "http/password" ) + hex2str( challenge );
response = hexstr( MD5( authsrc ) );
username = get_kb_item( "http/login" );
if(!strlen( username ) || IsMatchRegexp( username, "^[^a-z0-9]$" )){
	username = "";
}
url = "/Login?LOGIN.CHALLENGE=" + challenge + "&LOGIN.CHAPID=" + chapid + "&LOGIN.RESPONSE=" + response + "&LOGIN.USERNAME=" + username;
resp = http_send_recv( port: port, data: http_get( item: url, port: port ) );
if(!resp){
	exit( 0 );
}
cookie = egrep( pattern: "^Set-Cookie: *[^a-z0-9]PSpcV310=[0-9a-f]{32}", string: resp, icase: TRUE );
if(!cookie){
	exit( 0 );
}
cookie = ereg_replace( string: cookie, pattern: "^Set-", replace: "", icase: TRUE );
set_kb_item( name: "/tmp/http/auth/" + port, value: cookie );
exit( 0 );

