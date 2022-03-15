if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804882" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-8506", "CVE-2014-8505" );
	script_bugtraq_id( 70797, 70796 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-11-13 12:51:58 +0530 (Thu, 13 Nov 2014)" );
	script_name( "Etiko CMS Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Etiko CMS and
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'page_id' GET parameter
  to /loja/index.php script and 'article_id' parameter to /index.php script is not
  validated before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database allowing
  for the manipulation or disclosure of arbitrary data, and execute arbitrary HTML
  and script code in a users browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Etiko CMS version 2.14 and earlier." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128644" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/etiko", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(rcvRes && ContainsString( rcvRes, ">Etiko<" ) && ContainsString( rcvRes, "etikweb.com" )){
		url = dir + "/index.php?page_id=19\"><script>alert(document.cookie)</script>";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>", extra_check: ">Etiko<" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

