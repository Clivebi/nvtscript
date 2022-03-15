if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802493" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-11-15 16:26:54 +0530 (Thu, 15 Nov 2012)" );
	script_name( "netOffice Dwins Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51198" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/79962" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22590/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118010/netOffice-Dwins-1.4p3-SQL-Injection.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Input passed via the 'S_ATSEL' parameter to reports/export_leaves.php
  and reports/export_person_performance.php and 'id' parameter to
  expenses/approveexpense.php, calendar/exportcalendar.php,
  analysis/expanddimension.php, and analysis/changedimensionsortingorder.php
  is not properly sanitized before being used in a SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running netOffice Dwins and is prone to multiple
  sql injection vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow the attackers to manipulate
  SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "netOffice Dwins version 1.4p3 and prior" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/netoffice", "/Dwins", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/general/login.php";
	if(http_vuln_check( port: port, url: url, pattern: ">netOffice Dwins", check_header: TRUE, extra_check: make_list( ">Powered by netOffice Dwins",
		 "Log In<" ) )){
		url = dir + "/expenses/approveexpense.php?id=-1%20union%20select%200," + "SQL-Iniection-Test-&auth=-1&doc=-1";
		if(http_vuln_check( port: port, url: url, pattern: "'SQL-Iniection-Test-", check_header: TRUE, extra_check: make_list( "SQL syntax;",
			 "approveexpense.php" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

