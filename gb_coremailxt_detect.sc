if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113191" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-22 14:26:37 +0200 (Tue, 22 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Coremail XT Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Coremail XT Product Detection." );
	script_xref( name: "URL", value: "http://www.coremail.cn/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	buf = http_get_cache( item: dir, port: port );
	if(ContainsString( buf, "href=\"/coremail" ) || ContainsString( buf, "action=\"/coremail" )){
		set_kb_item( name: "coremail/detected", value: TRUE );
		version = "unknown";
		vers = eregmatch( pattern: "coremail/common/index_cmxt([0-9]+).jsp", string: buf );
		if(!isnull( vers[1] ) && strlen( vers[1] ) >= 2){
			vers_number = vers[1];
			version = vers_number[0] + "." + vers_number[1];
		}
		cpe = "cpe:/a:mailtech:coremail:";
		register_and_report_cpe( app: "Coremail XT", ver: version, concluded: vers[0], base: cpe, expr: "([0-9.]+)", insloc: dir, regPort: port, conclUrl: dir );
		exit( 0 );
	}
}
exit( 0 );

