if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805652" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-17 14:03:59 +0530 (Wed, 17 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell/Quest NetVault Backup Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Dell/Quest Netvault Backup.

  This script sends an HTTP GET request and tries to get the version from the response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.quest.com/products/netvault-backup/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, "<title>NetVault Backup</title>" ) && ContainsString( res, "serversummarypage.js" )){
	version = "unknown";
	vers = eregmatch( pattern: "Server:( NetVault/)?([0-9.]+)", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
	}
	set_kb_item( name: "dell/netvaultbackup/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:dell:netvault_backup:" );
	if(!cpe){
		cpe = "cpe:/a:dell:netvault_backup";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dell/Quest NetVault Backup", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

