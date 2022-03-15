if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106142" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-15 13:58:23 +0700 (Fri, 15 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Trend Micro Deep Discovery Inspector Detection" );
	script_tag( name: "summary", value: "Detection of Trend Micro Deep Discovery Inspector

The script sends a connection request to the server and attempts to detect the presence of Trend Micro Deep
Discovery Inspector and to extract its version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.trendmicro.com/en_us/business/products/network/advanced-threat-protection/inspector.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "Deep Discovery Inspector" ) && ContainsString( res, "scripts/strings.js" )){
	version = "unknown";
	url = "/scripts/strings.js";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	ver = eregmatch( pattern: "REMOTE_ONLINE_HELP_URL.*v([0-9._SP]+).*olh/\";", string: res );
	if(!isnull( ver[1] )){
		version = ereg_replace( string: ver[1], pattern: "_", replace: "." );
		concUrl = url;
	}
	set_kb_item( name: "deep_discovery_inspector/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.SP]+)", base: "cpe:/a:trend_micro:deep_discovery_inspector:" );
	if(!cpe){
		cpe = "cpe:/a:trend_micro:deep_discovery_inspector";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Trend Micro Deep Discovery Inspector", version: version, install: "/", cpe: cpe, concluded: ver[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

