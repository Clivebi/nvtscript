if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103732" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-0142", "CVE-2013-0144" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Qnap Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/927644" );
	script_xref( name: "URL", value: "http://www.h-online.com/security/news/item/Serious-vulnerabilities-in-QNAP-storage-and-surveillance-systems-1883263.html" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-07 10:32:41 +0200 (Fri, 07 Jun 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "http_server/banner" );
	script_require_ports( "Services/www", 80, 8080 );
	script_tag( name: "summary", value: "QNAP VioStor NVR firmware version 4.0.3 and possibly earlier versions and QNAP
  NAS contains multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  1. Improper Access Control

  VioStor NVR firmware version 4.0.3 and possibly earlier versions and QNAP NAS
  with the Surveillance Station Pro activated contains a hardcoded guest account
  and password which can be leveraged to login to the webserver. It has been
  reported that it is not possible to view or administer the guest account using
  the web interface.

  2. Cross-Site Request Forgery (CSRF).

  VioStor NVR firmware version 4.0.3 and possibly earlier versions contains a
  cross-site request forgery vulnerability could allow an attacker to add a new
  administrative account to the server by tricking an administrator to click on a
  malicious link while they are currently logged into the webserver." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: http server" )){
	exit( 0 );
}
url = "/cgi-bin/create_user.cgi";
req = "GET " + url + " HTTP/1.0\r\n" + "\r\n";
resp = http_send_recv( port: port, data: req );
if(!IsMatchRegexp( resp, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
userpass64 = base64( str: "guest:guest" );
req = "GET " + url + " HTTP/1.0\r\n" + "Authorization: Basic " + userpass64 + "\r\n" + "\r\n";
resp = http_send_recv( port: port, data: req );
if(IsMatchRegexp( resp, "^HTTP/1\\.[01] 200" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

