if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112300" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-11 11:32:22 +0200 (Mon, 11 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "DedeCMS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of DedeCMS." );
	script_xref( name: "URL", value: "http://www.dedecms.com/" );
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
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for file in make_list( "/" ) {
		url = dir + file;
		resp = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( resp, "^HTTP/1\\.[01] 200" ) && ( ContainsString( resp, "myajax = new DedeAjax(taget_obj,false,false,'','','');" ) || ContainsString( resp, "/dedeajax2.js" ) || ContainsString( resp, "/dedecms.css" ) )){
			set_kb_item( name: "dedecms/detected", value: TRUE );
			version = "unknown";
			register_and_report_cpe( app: "DedeCMS", ver: version, base: "cpe:/a:dedecms:dedecms:", expr: "([0-9].[0-9].[0-9])", insloc: install, regService: "www", regPort: port );
			exit( 0 );
		}
	}
}
exit( 0 );

