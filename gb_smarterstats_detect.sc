if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108255" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-18 10:31:53 +0200 (Wed, 18 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SmarterStats Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of SmarterStats.

  The script sends a connection request to the server and attempts to detect SmarterStats and its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
Port = http_get_port( default: 8080 );
res = http_get_cache( item: "/login.aspx", port: Port );
if(ContainsString( res, "Login to SmarterStats" ) || ContainsString( res, ">SmarterStats" )){
	version = "unknown";
	set_kb_item( name: "smarterstats/installed", value: TRUE );
	ver = eregmatch( pattern: "href=\"http://help.smartertools.com/smarterstats/v([0-9]+)/default.aspx[?]p=U&amp;v=([0-9.]+)", string: res );
	if(!isnull( ver[2] )){
		version = ver[2];
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:smartertools:smarterstats:" );
	if(!cpe){
		cpe = "cpe:/a:smartertools:smarterstats";
	}
	register_product( cpe: cpe, location: "/", port: Port, service: "www" );
	log_message( data: build_detection_report( app: "SmarterStats", version: version, install: "/", cpe: cpe ), port: Port );
}
exit( 0 );

