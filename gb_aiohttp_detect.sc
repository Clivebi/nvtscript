if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112839" );
	script_version( "2020-11-16T14:32:58+0000" );
	script_tag( name: "last_modification", value: "2020-11-16 14:32:58 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-16 09:14:11 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "aiohttp Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "aiohttp/banner" );
	script_tag( name: "summary", value: "HTTP based detection of aiohttp." );
	script_xref( name: "URL", value: "https://docs.aiohttp.org/" );
	exit( 0 );
}
CPE = "cpe:/a:aio-libs_project:aiohttp:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_remote_headers( port: port );
if(concl = egrep( string: buf, pattern: "^Server\\s*:.*aiohttp", icase: TRUE )){
	set_kb_item( name: "aio-libs_project/aiohttp/detected", value: TRUE );
	concl = chomp( concl );
	version = "unknown";
	ver = eregmatch( string: concl, pattern: "aiohttp/([0-9.]+)" );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	register_and_report_cpe( app: "aiohttp", ver: version, concluded: concl, base: CPE, expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

