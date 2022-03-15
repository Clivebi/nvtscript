if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103573" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_name( "Thomson Wireless VoIP Cable Modem Authentication Bypass" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/116719/Thomson-Wireless-VoIP-Cable-Modem-Authentication-Bypass.html" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-09-20 12:31:00 +0200 (Thu, 20 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Thomson Wireless VoIP Cable Modem TWG850-4 is prone to multiple authentication bypass vulnerabilities." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "Thomson" )){
	exit( 0 );
}
url = "/GatewaySettings.bin";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "ThomsonAP" ) && ContainsString( buf, "Broadcom" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

