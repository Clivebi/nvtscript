if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113239" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-01 11:40:00 +0200 (Wed, 01 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Web Remote Viewer Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects if a target is running the Web Remote Viewer software." );
	script_xref( name: "URL", value: "https://www.cctvcamerapros.com/Remote-Internet-DVR-Viewer-s/87.htm" );
	exit( 0 );
}
CPE = "cpe:/a:dvr:web_remote_viewer:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for url in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	buf = http_get_cache( port: port, item: "/" );
	if(!IsMatchRegexp( buf, "[Ww]{3}-[Aa]uthenticate:[ ]?[Bb]asic [Rr]ealm[ ]?=[ ]?\"[Ww][Ee][Bb][ ]?[Rr]emote[ ]?[Vv]iewer\"" )){
		continue;
	}
	set_kb_item( name: "web_remote_viewer/detected", value: TRUE );
	set_kb_item( name: "web_remote_viewer/http/port", value: port );
	version = "unknown";
	register_and_report_cpe( app: "Web Remote Viewer", ver: version, base: CPE, expr: "([0-9.]+)", insloc: url, regPort: port, conclUrl: url );
	break;
}
exit( 0 );

