if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901037" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-3366" );
	script_name( "An Image Gallery Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36680" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9636" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53148" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain information
  about directory and file locations." );
	script_tag( name: "affected", value: "An Image Gallery version 1.0 and prior." );
	script_tag( name: "insight", value: "Input passed to the 'path' parameter in 'navigation.php' is not
  properly verified before being used to generate and display folder contents." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running An Image Gallery and is prone to Directory
  Traversal vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/", "/image_gallery", "/gallery", "/album", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/main.php", port: port );
	if(ContainsString( rcvRes, "An image gallery" )){
		url = dir + "/navigation.php?path=../../../../../../../";
		if(http_vuln_check( port: port, url: url, pattern: "(WINDOWS|root)", check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

