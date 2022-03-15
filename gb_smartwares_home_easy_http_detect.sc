if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143110" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-12 02:16:34 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Smartwares HOME easy Detection" );
	script_tag( name: "summary", value: "Detection of Smartwares HOME easy

  The script sends a connection request to the server and attempts to detect Smartwares HOME easy." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.smartwares.eu/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "content=\"HOME easy\"" ) && ContainsString( res, "textArray[1]=\"Password:\"" )){
	version = "unknown";
	set_kb_item( name: "smartweares/home_easy/detected", value: TRUE );
	cpe = "cpe:/a:smartweares:home_easy";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Smartwares HOME easy", version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

