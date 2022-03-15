if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103021" );
	script_version( "2020-11-12T10:09:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-01-10 13:28:19 +0100 (Mon, 10 Jan 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Primal Fusion openSite Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/contentone/" );
	script_tag( name: "summary", value: "This host is running openSite, an open source website management
  software for making and operating powerful PHP/MySQL based websites." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/os", "/os/upload", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "<title>Primal Fusion openSite", string: buf, icase: TRUE )){
		set_kb_item( name: "primalfusion/opensite/detected", value: TRUE );
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "<title>Primal Fusion openSite v([^<]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		register_and_report_cpe( app: "Primal Fusion openSite", ver: vers, concluded: version[0], base: "cpe:/a:primalfusion:opensite:", expr: "^([0-9.]+)", insloc: install, regPort: port );
		exit( 0 );
	}
}
exit( 0 );

