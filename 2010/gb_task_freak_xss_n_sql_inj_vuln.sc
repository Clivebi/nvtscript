CPE = "cpe:/a:taskfreak:taskfreak%21";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800788" );
	script_version( "2021-10-01T12:59:49+0000" );
	script_tag( name: "last_modification", value: "2021-10-01 12:59:49 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2010-07-07 07:04:19 +0200 (Wed, 07 Jul 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-1520", "CVE-2010-1521" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TaskFreak! < 0.6.4 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_taskfreak_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "taskfreak/http/detected" );
	script_tag( name: "summary", value: "TaskFreak! is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2010-1520: Cross-site scripting (XSS) in logout.php

  - CVE-2010-1521: SQL injection (SQLi) in include/classes/tzn_user.php" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code and manipulate SQL queries by injecting arbitrary SQL code in a
  user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "TaskFreak! prior to version 0.6.4." );
	script_tag( name: "solution", value: "Update to version 0.6.4 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40025" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/512078/100/0/threaded" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/logout.php?tznMessage=<script>alert('VT-XSS-Testing')</script>";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert('VT-XSS-Testing')</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

