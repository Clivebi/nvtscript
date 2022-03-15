if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113059" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-30 10:23:24 +0100 (Thu, 30 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cambium Networks Services Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This scripts sends an HTTP GET request to figure out whether Cambium Networks Services Server is installed on the target host, and, if so, which version." );
	script_xref( name: "URL", value: "https://www.cambiumnetworks.com/products/management/cns-server/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	for file in make_list( "/",
		 "/index.html" ) {
		if( dir == "/" ) {
			url = file;
		}
		else {
			url = dir + file;
		}
		resp = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( resp, "<title>Cambium Networks Services Server</title>" ) && IsMatchRegexp( resp, "href=\"http://cambiumnetworks.com\"" )){
			version_match = eregmatch( pattern: "<i>\\(([0-9.]+)\\)</i>", string: resp );
			version = "unknown";
			if(version_match[1]){
				version = version_match[1];
			}
			set_kb_item( name: "cambium-networks/services-server/detected", value: TRUE );
			register_and_report_cpe( app: "Cambium Networks Services Server", ver: version, concluded: version_match[0], base: "cpe:/a:cambium-networks:services-server:", expr: "^([0-9.]+)", insloc: dir, regPort: port );
			exit( 0 );
		}
	}
}

