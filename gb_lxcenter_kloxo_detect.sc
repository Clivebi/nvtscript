if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103977" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "LxCenter Kloxo Detection" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-02-22 22:54:04 +0700 (Sat, 22 Feb 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7778 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://github.com/lxcenter/kloxo" );
	script_tag( name: "summary", value: "This host is running LxCenter Kloxo. Kloxo is a fully scriptable
  hosting platform." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 7778 );
buf = http_get_cache( item: "/login/", port: port );
if(!buf){
	exit( 0 );
}
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "Kloxo", string: buf, icase: TRUE )){
	install = "/";
	version = "unknown";
	vers = eregmatch( string: buf, pattern: ">Kloxo.* ([0-9.]+[a-z]-[0-9]+)<", icase: TRUE );
	if(!isnull( vers[1] )){
		version = chomp( vers[1] );
	}
	set_kb_item( name: "Kloxo/installed", value: TRUE );
	set_kb_item( name: "www/" + port + "/kloxo", value: version );
	cpe = build_cpe( value: version, exp: "^([0-9.]+[a-z]-[0-9]+)", base: "cpe:/a:lxcenter:kloxo:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:lxcenter:kloxo";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "LxCenter Kloxo", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
}
exit( 0 );

