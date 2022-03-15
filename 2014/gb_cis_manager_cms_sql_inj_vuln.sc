if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804558" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-2847" );
	script_bugtraq_id( 66590 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-04-28 19:58:39 +0530 (Mon, 28 Apr 2014)" );
	script_name( "CIS Manager 'TroncoID' Parameter SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/32660" );
	script_xref( name: "URL", value: "http://www.cnnvd.org.cn/vulnerability/show/cv_id/2014040155" );
	script_tag( name: "summary", value: "The host is installed with CIS Manager and is prone to sql injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able
  execute sql query or not." );
	script_tag( name: "insight", value: "Input passed via the 'TroncoID' GET parameter to default.asp is not
  properly sanitised before being used in a sql query." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML or
  script code and manipulate SQL queries in the backend database allowing
  for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_asp( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/cis", "/cms", "/cismanager", "/cismanagercms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/default.asp", port: http_port );
	if(ContainsString( rcvRes, ">CIS Manager<" ) && ContainsString( rcvRes, ">Construtiva" )){
		url = dir + "/default.asp?TroncoID='SQLInjTest";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "'SQLInjTest'", extra_check: ">error '80040e14'<" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

