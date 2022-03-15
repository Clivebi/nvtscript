CPE = "cpe:/o:loxone:miniserver_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107045" );
	script_version( "2021-01-21T10:48:53+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Loxone Smart Home Default Admin Login (HTTP)" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials admin:admin." );
	script_tag( name: "solution", value: "Change the username and password." );
	script_tag( name: "summary", value: "The remote Loxone installation has default credentials set." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-01-21 10:48:53 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-09-07 13:18:59 +0200 (Wed, 07 Sep 2016)" );
	script_xref( name: "URL", value: "https://osvdb.info/OSVDB-98155" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_loxone_miniserver_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "loxone/miniserver/detected" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
func newHandshakekey(  ){
	rand = rand_str( length: 16, charset: "0123456789" );
	return base64( str: rand );
}
username = "admin";
password = "admin";
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
rand = rand_str( length: 17, charset: "0123456789" );
req = NASLString( "GET /jdev/sys/getkey?0.", rand, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept-Encoding: identity\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( res, "HTTP/1\\.[01] 200" ) || !ContainsString( res, "{\"LL\": {" )){
	exit( 0 );
}
json_key = eregmatch( pattern: "\"LL\": [{] \"control\": \"dev/sys/getkey\", \"value\": \"([A-F0-9]+)\", \"Code\": \"200\"}}", string: res, icase: TRUE );
key = json_key[1];
if(!key){
	exit( 0 );
}
passphrase = username + ":" + password;
key = hex2str( key );
protocol = HMAC_SHA1( data: passphrase, key: key );
protocol1 = hexstr( protocol );
websockey_key = newHandshakekey();
req2 = NASLString( "GET /ws HTTP/1.1", "\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: en-US,en;q=0.5\\r\\n", "Accept-Encoding: identity\\r\\n", "Sec-WebSocket-Version: 13\\r\\n", "origin: http://", host, "\\r\\n", "Sec-WebSocket-Protocol: ", protocol1, "\\r\\n", "Sec-WebSocket-Extensions: permessage-deflate\\r\\n", "Sec-WebSocket-Key: ", websockey_key, "\\r\\n", "Connection: keep-alive, Upgrade\\r\\n", "Pragma: no-cache\\r\\n", "Cache-Control: no-cache\\r\\n", "Upgrade: websocket\\r\\n", "\\r\\n" );
res2 = http_keepalive_send_recv( port: port, data: req2 );
if(IsMatchRegexp( res2, "HTTP/1\\.[01] 101 Web Socket Protocol Handshake" ) && ContainsString( res2, "Sec-WebSocket-Accept" )){
	report = "It was possible to login into Loxone web interface using username `admin` and password `admin`.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

