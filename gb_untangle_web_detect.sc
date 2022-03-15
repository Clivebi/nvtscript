if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105813" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-18 15:32:04 +0200 (Mon, 18 Jul 2016)" );
	script_name( "Untangle NG Firewall Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Untangle NG Firewall." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/auth/login";
buf = http_get_cache( item: url, port: port );
if(ContainsString( buf, "<title>Untangle Administrator Login</title>" ) && ContainsString( buf, "username" ) && ContainsString( buf, "password" )){
	cpe = "cpe:/a:untangle:ng-firewall";
	set_kb_item( name: "untangle/installed", value: TRUE );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( port: port, data: "The Untangle NG Firewall Webinterface is running at this port.\nCPE: cpe:/a:untangle:ng-firewall" );
}
exit( 0 );

