if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802868" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-18 16:14:31 +0530 (Mon, 18 Jun 2012)" );
	script_name( "Bluadmin Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://1337day.com/exploits/18644" );
	script_xref( name: "URL", value: "http://bot24.blogspot.in/2012/06/bluadmin-sql-injection.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/113779/bluadmin-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause SQL injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "Bluadmin" );
	script_tag( name: "insight", value: "The input passed via 'ver' parameter to 'get_imagesf.php' and
  'get_flash_info.php' is not properly sanitised before being used in SQL
  queries, which allows attackers to execute arbitrary SQL commands in the
  context of an affected application or site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Bluadmin and is prone to multiple SQL
  injection vulnerabilities." );
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
for dir in nasl_make_list_unique( "/", "/bluadmin", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/get_flash_info.php?ver=1'";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "mysql_fetch_array\\(\\): supplied argument is " + "not a valid MySQL result", extra_check: make_list( "get_flash_info.php",
		 "extract\\(\\)",
		 "eval\\(\\)'d code" ) )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

