if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802434" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-11 14:44:53 +0530 (Mon, 11 Jun 2012)" );
	script_name( "KBPublisher Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://1337day.com/exploits/18467" );
	script_xref( name: "URL", value: "http://mondoristoranti.com/kbpublisher-v4-0-multiple-vulnerabilities/" );
	script_xref( name: "URL", value: "http://www.allinfosec.com/2012/06/07/webapps-0day-kbpublisher-v4-0-multiple-vulnerabilities/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal cookie
  based authentication credentials, compromise the application, access or modify
  data or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "KBPublisher version 4.0" );
	script_tag( name: "insight", value: "- Input passed via the 'Type' parameter to 'browser.html' is not
  properly sanitised before being returned to the user.

  - Input passed via the 'id' parameter to 'admin/index.php' is not properly
  sanitised before being used in SQL queries.

  - Input passed via the 'sid' parameter to 'index.php' is not properly
  sanitised before being used ." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running KBPublisher and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/", "/kb", "/kbp", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(!res){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">KBPublisher<" ) && ContainsString( res, "Knowledge base software" )){
		url = dir + "/?&sid=\"><script>alert(document.cookie)</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>", extra_check: ">KBPublisher<" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

