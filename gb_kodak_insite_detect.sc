if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106820" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-05-22 16:58:14 +0700 (Mon, 22 May 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Kodak inSite Detection" );
	script_tag( name: "summary", value: "Detection of Kodak inSite.

The script sends a connection request to the server and attempts to detect Kodak inSite and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.kodak.com/US/en/prinergy-workflow/platform/insite-prepress-portal/default.htm" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/Site/Pages/login.aspx";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "Kodak InSite" ) && ContainsString( res, "CSWStyle_PoweredBy" ) && ContainsString( res, "kstrLoginPageURL" )){
	version = "unknown";
	vers = eregmatch( pattern: "&amp;Version=([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "kodak_insite/version", value: version );
	}
	set_kb_item( name: "kodak_insite/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kodak:insite:" );
	if(!cpe){
		cpe = "cpe:/a:kodak:insite";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Kodak InSite", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

