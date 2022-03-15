if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113203" );
	script_version( "2021-07-08T09:33:39+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 09:33:39 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-05-29 15:42:35 +0200 (Tue, 29 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Monstra CMS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Monstra CMS." );
	script_xref( name: "URL", value: "http://monstra.org/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/monstra", http_cgi_dirs( port: port ) ) {
	location = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( buf, "<a href=\"http://monstra.org\" target=\"_blank\">Monstra</a>" ) || ContainsString( buf, "<meta name=\"generator\" content=\"Powered by Monstra" )){
		set_kb_item( name: "monstra_cms/detected", value: TRUE );
		set_kb_item( name: "monstra_cms/http/detected", value: TRUE );
		version = "unknown";
		vers = eregmatch( string: buf, pattern: "<a href=\"http://monstra.org\" target=\"_blank\">Monstra</a>[ ]{0,}([0-9.]+)[ ]{0,}</div>" );
		if( !isnull( vers[1] ) ){
			version = vers[1];
		}
		else {
			vers = eregmatch( string: buf, pattern: "Powered by Monstra ([0-9.]+)" );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
		register_and_report_cpe( app: "Monstra CMS", ver: version, concluded: vers[0], base: "cpe:/a:monstra:monstra:", expr: "([0-9.]+)", insloc: location, regPort: port, conclUrl: location );
		exit( 0 );
	}
}
exit( 0 );

