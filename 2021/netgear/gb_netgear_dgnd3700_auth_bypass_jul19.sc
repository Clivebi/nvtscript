CPE = "cpe:/o:netgear:dgnd3700_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117531" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 12:12:38 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-17373" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "NETGEAR DGND3700 Authentication Bypass Vulnerability (Dec 2020)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_netgear_dgnd3700_http_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "netgear/dgnd3700/http/detected" );
	script_tag( name: "summary", value: "NETGEAR DGN3700 devices are prone to an authentication bypass
  vulnerability." );
	script_tag( name: "insight", value: "A flaw exists which allows accessing router management pages
  using an authentication bypass." );
	script_tag( name: "vuldetect", value: "Sends a HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "An unauthenticated attacker might access or read sensitive
  information which could lead to a full compromise of the router." );
	script_tag( name: "affected", value: "NETGEAR DGND3700 devices in unknown firmware versions." );
	script_tag( name: "solution", value: "No known solution is available as of 02nd August, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/WAN_wan.htm";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
url += "?pic.gif";
req = http_get( port: port, item: url );
http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(http_vuln_check( port: port, url: url, pattern: "<title>WAN Setup", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

