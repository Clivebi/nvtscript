if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103530" );
	script_bugtraq_id( 54803 );
	script_version( "2020-10-29T15:35:19+0000" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_name( "Tickets CAD Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/20268/" );
	script_xref( name: "URL", value: "http://www.ticketscad.org" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-08-06 12:26:58 +0200 (Mon, 06 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Tickets CAD is prone to multiple vulnerabilities.

1. A Reflected XSS vulnerability exists in the search function, search.php within the application.

2. A Stored XSS vulnerability exists in log.php while creating a new log entry.

3. Information disclosure exist which allows users even the guest account to view the tables of the sql database." );
	script_tag( name: "affected", value: "Tickets CAD 2.20G is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/tickets", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/main.php";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "Welcome to Tickets" )){
		co = eregmatch( pattern: "Set-Cookie: ([^;]+)", string: buf );
		if(isnull( co[1] )){
			exit( 0 );
		}
		c = co[1];
		host = http_host_name( port: port );
		ex = "frm_user=guest&frm_passwd=guest&frm_daynight=Day&frm_referer=http%3A%2F%2F" + host + "%2FDAC213%2Ftop.php";
		len = strlen( ex );
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Cookie: ", c, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", ex );
		result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( result, "HTTP/1.. 302" ) && ContainsString( result, "main.php?log_in=1" )){
			url = dir + "/tables.php";
			req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", c, "\\r\\n", "\\r\\n" );
			result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(ContainsString( result, "Available 'tickets ' tables" ) && ContainsString( result, "submit();\"> user" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

