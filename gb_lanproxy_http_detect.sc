if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145289" );
	script_version( "2021-02-01T06:53:28+0000" );
	script_tag( name: "last_modification", value: "2021-02-01 06:53:28 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-01 06:14:07 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "LanProxy Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of LanProxy." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8090 );
	script_mandatory_keys( "LPS/banner" );
	script_xref( name: "URL", value: "https://github.com/ffay/lanproxy" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8090 );
banner = http_get_remote_headers( port: port );
if(!IsMatchRegexp( banner, "Server\\s*:\\s*LPS" )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "lanproxy-config" ) && ContainsString( res, "\" - LanProxy\"" )){
	version = "unknown";
	vers = eregmatch( pattern: "Server\\s*:\\s*LPS\\-([0-9.]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "lanproxy/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:lanproxy_project:lanproxy:" );
	if(!cpe){
		cpe = "cpe:/a:lanproxy_project:lanproxy";
	}
	register_product( cpe: cpe, port: port, location: "/", service: "www" );
	log_message( data: build_detection_report( app: "LanProxy", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

