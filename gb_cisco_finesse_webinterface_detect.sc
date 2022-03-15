if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105624" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-26 12:59:19 +0200 (Tue, 26 Apr 2016)" );
	script_name( "Cisco Finesse Webinterface Detection" );
	script_tag( name: "summary", value: "This scripte performs HTTP based detection of the Cisco Finesse Webinterface" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/desktop/container/";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
cpe = "cpe:/a:cisco:finesse";
if(ContainsString( buf, ">Sign in to Cisco Finesse</title>" ) && ContainsString( buf, "j_security_check" ) && ContainsString( buf, "Cisco Systems, Inc" )){
	register_product( cpe: cpe, location: "/desktop/container/", port: port, service: "www" );
	log_message( port: port, data: "The Cisco Finesse Webinterface is running at this port.\nCPE: " + cpe + "\nLocation: /desktop/" );
	exit( 0 );
}
exit( 0 );

