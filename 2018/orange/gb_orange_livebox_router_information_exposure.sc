if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114055" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-12-27 18:03:44 +0100 (Thu, 27 Dec 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_name( "Orange Livebox Router Information Exposure" );
	script_dependencies( "gb_orange_livebox_router_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "orange/livebox/detected" );
	script_xref( name: "URL", value: "https://badpackets.net/over-19000-orange-livebox-adsl-modems-are-leaking-their-wifi-credentials/" );
	script_cve_id( "CVE-2018-20377" );
	script_tag( name: "summary", value: "The remote installation of Orange Livebox is prone to
  an information exposure vulnerability. The webserver leaks the WiFi security protocol, SSID, and password in plain text." );
	script_tag( name: "impact", value: "This vulnerability might be exploited to obtain login information, if the leaked password
  matches the one used to log in as an administrator. Furthermore, people exploiting this vulnerability locally could obtain
  authenticated access to the WiFi access point." );
	script_tag( name: "insight", value: "This vulnerability affects all firmware versions before 00.96.00.96.613E." );
	script_tag( name: "vuldetect", value: "Sends a specific HTTP GET request to the host and checks if the information is being leaked." );
	script_tag( name: "solution", value: "Update to firmware version 00.96.00.96.613E or later. Also make sure the WiFi password never
  matches the password of the administrator in case this ever happens again." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
CPE = "cpe:/h:orange:livebox";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/get_getnetworkconf.cgi";
req = http_get_req( port: port, url: url );
res = http_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "<html>\\s*<body>\\s*Orange-[0-9a-zA-Z_]+<BR>\\s*[0-9a-zA-Z_]+<BR>" )){
	report = "It was possible to obtain the SSID and the WiFi password.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

