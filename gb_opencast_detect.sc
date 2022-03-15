if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113057" );
	script_version( "2021-06-17T10:14:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 10:14:19 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Opencast Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Opencast." );
	script_xref( name: "URL", value: "https://www.opencast.org" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", "/admin-ng", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for file in make_list( "/",
		 "/login.html" ) {
		url = dir + file;
		resp = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( resp, "<title>Opencast[^<]{0,}" ) && ( ContainsString( resp, "version.version\"> Opencast" ) || ContainsString( resp, "href=\"http://www.opencastproject.org\"" ) || ContainsString( resp, "<span>Welcome to Opencast</span>" ) || ContainsString( resp, "translate=\"LOGIN.WELCOME\">" ) )){
			set_kb_item( name: "opencast/detected", value: TRUE );
			version = "unknown";
			version_url = "/sysinfo/bundles/version?prefix=opencast";
			resp = http_get_cache( item: version_url, port: port );
			version_match = eregmatch( pattern: ".*\"version\":\"([0-9]+\\.[0-9]+\\.?([0-9]+)?)", string: resp );
			if(version_match[1]){
				version = version_match[1];
				concluded_url = http_report_vuln_url( port: port, url: version_url, url_only: TRUE );
			}
			register_and_report_cpe( app: "Opencast", ver: version, concluded: version_match[0], base: "cpe:/a:opencast:opencast:", expr: "([0-9.]+)", insloc: install, regService: "www", regPort: port, conclUrl: concluded_url );
			exit( 0 );
		}
	}
}

