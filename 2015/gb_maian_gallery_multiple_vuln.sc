if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805648" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-09 15:25:55 +0530 (Tue, 09 Jun 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "Maian Gallery Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with Maian Gallery
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Multiple flaws exist as

  - Input passed to the 'index.php' script is not properly sanitised before being
    returned to the user.

  - Input passed to the 'cryptographp.php' script is not properly sanitised
    before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to  execute arbitrary script code in a user's browser within the
  trust relationship between their browser and the server and maliciously
  control the way a web application functions." );
	script_tag( name: "affected", value: "Maian Gallery version 2.0" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132154" );
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
mgPort = http_get_port( default: 80 );
if(!http_can_host_php( port: mgPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/gallery", "/maian_gallery", http_cgi_dirs( port: mgPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: mgPort );
	if(ContainsString( rcvRes, "Maian Gallery" )){
		url = dir + "/index.php?cmd=search&keywords=1&search_type=";
		if(http_vuln_check( port: mgPort, url: url, check_header: FALSE, pattern: "You have an error in your SQL syntax" )){
			security_message( port: mgPort );
			exit( 0 );
		}
	}
}
exit( 99 );

