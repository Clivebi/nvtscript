if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107234" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-09-05 16:22:38 +0700 (Tue, 05 Sep 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "WPJobBoard Detection" );
	script_tag( name: "summary", value: "Detection of WPJobBoard.

The script sends a connection request to the server and attempts to detect WPJobBoard and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://wpjobboard.net/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "target=\"_blank\">WPJobBoard</a></p>" ) || ContainsString( res, "wp-content/plugins/wpjobboard/public/" )){
	version = "unknown";
	ver = eregmatch( pattern: "wpjobboard/public/js/frontend.js\\?ver=([0-9.]+)'></script>", string: res );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "wpjobboard/version", value: version );
	}
	set_kb_item( name: "wpjobboard/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:wpjobboard:wpjobboard:" );
	if(!cpe){
		cpe = "cpe:/a:wpjobboard:wpjobboard";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "WPJobBoard", version: version, install: "/", cpe: cpe, concluded: ver[0] ), port: port );
}
exit( 0 );

