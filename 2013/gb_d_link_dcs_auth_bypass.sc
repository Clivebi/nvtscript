if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103647" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "D-Link DCS Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/119902/D-Link-DCS-Cameras-Authentication-Bypass-Command-Execution.html" );
	script_xref( name: "URL", value: "http://www.d-link.com" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-01-30 11:53:42 +0100 (Wed, 30 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "DCS-9/banner" );
	script_tag( name: "solution", value: "Updates are available" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "D-Link DCS is prone to an authentication-bypass vulnerability.

Attackers can exploit this issue to bypass authentication and to execute commands
due to a remote information disclosure of the configuration.

Affected devices:

  * D-Link DCS-930L, firmware version 1.04

  * D-Link DCS-932L, firmware version 1.02" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "realm=\"DCS-9" )){
	exit( 0 );
}
url = "/frame/GetConfig";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "Content-Transfer-Encoding: binary" ) && ContainsString( buf, "filename=\"Config.CFG\"" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

