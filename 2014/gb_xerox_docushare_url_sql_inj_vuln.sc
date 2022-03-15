if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804556" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 66922 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-04-24 15:12:51 +0530 (Thu, 24 Apr 2014)" );
	script_name( "Xerox DocuShare URL SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Xerox DocuShare and is prone to multiple
  sql injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not." );
	script_tag( name: "insight", value: "Input appended to the URL after /docushare/dsweb/ResultBackgroundJobMultiple/1
  is not properly sanitised before being used in SQL queries." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML or
  script code and manipulate SQL queries in the backend database allowing
  for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Xerox DocuShare version 6.5.3 Patch 6, 6.6.1 Update 1, and 6.6.1 Update 2,
  Prior versions may also be affected." );
	script_tag( name: "solution", value: "Apply the hotfix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57996" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/32886" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/126171" );
	script_xref( name: "URL", value: "https://gist.github.com/brandonprry/10745681" );
	script_xref( name: "URL", value: "http://www.xerox.com/download/security/security-bulletin/a72cd-4f7a54ce14460/cert_XRX14-003_V1.0.pdf" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/docushare", "/share", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/dsweb/HomePage" ), port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(ContainsString( rcvRes, "Docushare<" ) && ContainsString( rcvRes, "Xerox.com<" )){
		url = dir + "/dsweb/ResultBackgroundJobMultiple/'SQL-Inj-Test";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: ">SQL error.<", extra_check: make_list( "Error Code: 1501",
			 "SQL-Inj-Test" ) )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

