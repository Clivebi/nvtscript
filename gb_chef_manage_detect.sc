if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106677" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-21 12:20:58 +0700 (Tue, 21 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Chef Manage Detection" );
	script_tag( name: "summary", value: "Detection of Chef Manage

The script sends a HTTP connection request to the server and attempts to detect the presence of Chef Manage and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://docs.chef.io/manage.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/login" );
if(ContainsString( res, "<title>Sign In - Chef Manage</title>" ) && ContainsString( res, "If you have questions or you're stuck" )){
	version = "unknown";
	req = http_get( port: port, item: "/changelog" );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "<h2 id=\"(section|unreleased)\">([0-9.]+)", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
		set_kb_item( name: "chef_manage/version", value: version );
	}
	set_kb_item( name: "chef_manage/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:chef:chef_manage:" );
	if(!cpe){
		cpe = "cpe:/a:chef:chef_manage";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Chef Manage", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

