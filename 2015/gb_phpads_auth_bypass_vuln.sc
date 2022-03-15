if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805321" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-13 13:48:08 +0530 (Tue, 13 Jan 2015)" );
	script_name( "PHPads Authentication Bypass Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "This host is installed with PHPads
  and is prone to Authentication Bypass vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET
  request and check whether it is able to read 'ads.dat' file or not." );
	script_tag( name: "insight", value: "The flaws is due to 'ads.dat' file
  which is in web root." );
	script_tag( name: "impact", value: "Successful exploitation allows to bypass
  the authentication mechanism by creating the cookies 'user' and 'pass'
  and assigning them the corresponding values taken from the 'ads.dat' file." );
	script_tag( name: "affected", value: "PHPads version 2.0." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35535" );
	script_xref( name: "URL", value: "http://secunia.com/community/advisories/33580" );
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
phpPort = http_get_port( default: 80 );
if(!http_can_host_php( port: phpPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/phpads", "/ads", http_cgi_dirs( port: phpPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/admin.php" ), port: phpPort );
	if(ContainsString( res, "<title>PHPads" ) && ContainsString( res, ">PHPads<" )){
		reqads = http_get( item: NASLString( dir, "/ads.dat" ), port: phpPort );
		resads = http_keepalive_send_recv( port: phpPort, data: reqads );
		if(IsMatchRegexp( resads, "user=[0-9a-zA-Z]+" ) && IsMatchRegexp( resads, "pass=[0-9a-zA-Z]+" )){
			report = http_report_vuln_url( port: phpPort, url: dir + "/ads.dat" );
			security_message( port: phpPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

