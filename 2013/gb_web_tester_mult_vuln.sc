if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804027" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-10-16 12:57:49 +0530 (Wed, 16 Oct 2013)" );
	script_name( "WebTester Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running WebTester and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check whether it is able to read sensitive
  information or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Input passed via 'TestID' parameter to 'startTest.php' script is not properly
  sanitized before being used in the code.

  - The application is not verifying permissions when accessing certain files
  like phpinfo.php and '/tiny_mce/plugins/filemanager/InsertFile/insert_file.php'

  - Application is not removing installed files after installation." );
	script_tag( name: "affected", value: "WebTester version 5.x, Other versions may also be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to manipulate SQL queries
  by injecting arbitrary SQL code, Upload arbitrary file, and disclose sensitive
  information." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/21384" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/123629" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/webtester-5x-sql-injection-file-upload-disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/webtester", "/webtester5", "/tester", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: http_port );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">WebTester" )){
		url = dir + "/phpinfo.php";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: ">phpinfo\\(\\)<", extra_check: ">Configuration File" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

