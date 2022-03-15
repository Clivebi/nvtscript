if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10498" );
	script_version( "2021-02-15T07:14:40+0000" );
	script_tag( name: "last_modification", value: "2021-02-15 07:14:40 +0000 (Mon, 15 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 12141 );
	script_xref( name: "OWASP", value: "OWASP-CM-001" );
	script_name( "Test HTTP dangerous methods" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2000 Michel Arboi" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Use access restrictions to these dangerous HTTP methods
  or disable them completely." );
	script_tag( name: "summary", value: "Misconfigured web servers allows remote clients to perform
  dangerous HTTP methods such as PUT and DELETE." );
	script_tag( name: "vuldetect", value: "Checks if dangerous HTTP methods such as PUT and DELETE are
  enabled and can be misused to upload or delete files." );
	script_tag( name: "impact", value: "- Enabled PUT method: This might allow an attacker to upload
  and run arbitrary code on this web server.

  - Enabled DELETE method: This might allow an attacker to delete additional files on this web
  server." );
	script_tag( name: "affected", value: "Web servers with enabled PUT and/or DELETE methods." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
report_put_success = "We could upload the following files via the PUT method at this web server:\n";
report_delete_success = "We could delete the following files via the DELETE method at this web server:\n";
report_put_no_exploit = "Although we could not exploit this it seems that the PUT method is enabled (auth protected) at this web server for the following directories:\n";
report_delete_no_exploit = "Although we could not exploit this it seems that the DELETE method is enabled (auth protected) at this web server for the following directories:\n";
check_text = "A quick brown fox jumps over the lazy dog";
func exists( file, port ){
	var file, port;
	if( http_vuln_check( port: port, url: file, pattern: check_text, check_header: TRUE ) ){
		return TRUE;
	}
	else {
		return FALSE;
	}
}
port = http_get_port( default: 80 );
put_success = FALSE;
delete_success = FALSE;
put_no_exploit = FALSE;
delete_no_exploit = FALSE;
vuln = FALSE;
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if( dir == "/" ){
		url = "*";
	}
	else {
		url = dir + "/";
	}
	req = http_get( item: url, port: port );
	req = str_replace( string: req, find: "GET", replace: "OPTIONS", count: 1 );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	allow = egrep( string: res, pattern: "^Allow:" );
	if(url == "*"){
		url = "/";
	}
	for(i = 1;exists( file: url + "puttest" + i + ".html", port: port );i++){
		if(i > 3){
			continue;
		}
	}
	file = url + "puttest" + rand() + ".html";
	c = crap( length: 77, data: check_text );
	req = http_put( item: file, port: port, data: c );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if( exists( port: port, file: file ) ){
		put_success = TRUE;
		vuln = TRUE;
		report_put_success += "\n" + http_report_vuln_url( port: port, url: file, url_only: TRUE );
	}
	else {
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 401" ) && ContainsString( allow, "PUT" )){
			put_no_exploit = TRUE;
			vuln = TRUE;
			report_put_no_exploit += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
	if( exists( port: port, file: file ) ){
		req = http_delete( item: file, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		e = exists( port: port, file: file );
	}
	else {
		e = TRUE;
	}
	if( !e ){
		delete_success = TRUE;
		vuln = TRUE;
		report_delete_success += "\n" + http_report_vuln_url( port: port, url: file, url_only: TRUE );
	}
	else {
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 401" ) && ContainsString( allow, "DELETE" )){
			delete_no_exploit = TRUE;
			vuln = TRUE;
			report_delete_no_exploit += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
}
if(vuln){
	security_report = "";
	log_report = "";
	if(put_success){
		security_report += report_put_success + "\n\n";
	}
	if(delete_success){
		security_report += report_delete_success + "\n\n";
	}
	if(put_no_exploit){
		log_report += report_put_no_exploit + "\n\n";
	}
	if(delete_no_exploit){
		log_report += report_delete_no_exploit + "\n\n";
	}
	if(strlen( security_report )){
		security_message( port: port, data: security_report );
	}
	if(strlen( log_report )){
		log_message( port: port, data: log_report );
	}
	exit( 0 );
}
exit( 99 );

