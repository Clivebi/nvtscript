if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801840" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-09-14T06:17:58+0000" );
	script_tag( name: "last_modification", value: "2020-09-14 06:17:58 +0000 (Mon, 14 Sep 2020)" );
	script_tag( name: "creation_date", value: "2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "XWiki Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of XWiki." );
	script_xref( name: "URL", value: "https://www.xwiki.org" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/xwiki/bin/login/XWiki/XWikiLogin" );
if(ContainsString( res, "XWiki.XWikiLogin" ) && ContainsString( res, "data-xwiki-wiki" )){
	version = "unknown";
	install = "/xwiki";
	vers = eregmatch( pattern: "\"xwikiplatformversion\">.*XWiki[^0-9]+([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "xwiki/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:xwiki:xwiki:" );
	if(!cpe){
		cpe = "cpe:/a:xwiki:xwiki";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "XWiki", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

