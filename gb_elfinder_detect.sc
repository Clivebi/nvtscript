if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113323" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-11 11:46:47 +0100 (Fri, 11 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "elFinder Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether elFinder is installed on the target system
  and if so, tries to figure out the version." );
	script_xref( name: "URL", value: "https://studio-42.github.io/elFinder/" );
	exit( 0 );
}
CPE = "cpe:/a:studio42:elfinder:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for location in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	url = location;
	if(url == "/"){
		url = "";
	}
	buf = http_get_cache( port: port, item: location );
	if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || !IsMatchRegexp( buf, "elfinder" )){
		continue;
	}
	link = eregmatch( string: buf, pattern: "(src|href)=\"/?([^\"]*elfinder\\.(min|full|version)\\.?(css|js))\"", icase: TRUE );
	if(isnull( link[2] )){
		continue;
	}
	set_kb_item( name: "studio42/elfinder/detected", value: TRUE );
	conclUrl = url + "/" + link[2];
	version = "unknown";
	buf = http_get_cache( port: port, item: conclUrl );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		buf = ereg_replace( pattern: "[\r\n]+", string: buf, replace: "" );
		ver = eregmatch( string: buf, pattern: "elFinder - file manager for web[ ]*\\*[ ]*Version ([0-9.]+)", icase: TRUE );
		if(isnull( ver[1] )){
			ver = eregmatch( string: buf, pattern: "elFinder[.][^.]*[.]?version[ ]*=[ ]*.([0-9.]+).", icase: TRUE );
		}
		if(!isnull( ver[1] )){
			version = ver[1];
		}
	}
	register_and_report_cpe( app: "elFinder", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: location, regPort: port, regService: "www", conclUrl: conclUrl );
	exit( 0 );
}
exit( 0 );

