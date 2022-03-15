CPE = "cpe:/o:netgear:dgn2200_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146209" );
	script_version( "2021-07-05T07:37:07+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 07:37:07 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 04:51:51 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NETGEAR DGN2200v1 < 1.0.0.60 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_netgear_dgn2200_http_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "netgear/dgn2200/http/detected" );
	script_tag( name: "summary", value: "NETGEAR DGN2200v1 devices are prone to multiple
  vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2019-17373: Accessing router management pages using authentication bypass

  - Deriving saved router credentials via a cryptographic side-channel

  - Retrieving secrets stored in the device" );
	script_tag( name: "vuldetect", value: "Sends a HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "An unauthenticated attacker might access or read sensitive
  information which could lead to a full compromise of the router." );
	script_tag( name: "affected", value: "NETGEAR DGN2200v1 prior to firmware version 1.0.0.60." );
	script_tag( name: "solution", value: "Update to version 1.0.0.60 or later." );
	script_xref( name: "URL", value: "https://kb.netgear.com/000062646/Security-Advisory-for-Multiple-HTTPd-Authentication-Vulnerabilities-on-DGN2200v1" );
	script_xref( name: "URL", value: "https://www.microsoft.com/security/blog/2021/06/30/microsoft-finds-new-netgear-firmware-vulnerabilities-that-could-lead-to-identity-theft-and-full-system-compromise/" );
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

