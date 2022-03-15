if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800803" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1510" );
	script_bugtraq_id( 34335 );
	script_name( "KoschtIT Image Gallery Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8334" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/378734.php" );
	script_xref( name: "URL", value: "http://koschtit.tabere.net/forum/showthread.php?tid=6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary commands to
  retrieve local system related files and gain sensitive information." );
	script_tag( name: "affected", value: "KoschtIT Image Gallery version 1.82 and prior." );
	script_tag( name: "insight", value: "Improper validation check while processing user supplied input in the file
  parameter for the files 'ki_makepic.php' and 'ki_nojsdisplayimage.php' under
  ki_base directory." );
	script_tag( name: "solution", value: "Upgrade to KoschtIT Image Gallery version 2.0 Beta 1." );
	script_tag( name: "summary", value: "This host is running KoschtIT Image Gallery and is prone to multiple
  Directory Traversal vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
koschITPort = http_get_port( default: 80 );
if(!http_can_host_php( port: koschITPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/kos2", "/koschtit", "/koschtit2", "/", http_cgi_dirs( port: koschITPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/changelog.txt", port: koschITPort );
	rcvRes = http_keepalive_send_recv( port: koschITPort, data: sndReq );
	if(ContainsString( rcvRes, "KoschtIT Image Gallery" )){
		ver = eregmatch( pattern: "Gallery ([0-9.]+)(beta)?([0-9]+)?", string: rcvRes );
		if(ver[1] != NULL){
			if( ver[1] != NULL && ver[3] != NULL ){
				version = ver[1] + "." + ver[3];
			}
			else {
				version = ver[1];
			}
		}
		if(version != NULL){
			if(version_is_less_equal( version: version, test_version: "1.82" )){
				security_message( port: koschITPort, data: "The target host was found to be vulnerable." );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

