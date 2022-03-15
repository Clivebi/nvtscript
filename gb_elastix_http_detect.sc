if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117269" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-22 09:59:02 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Elastix Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Elastix." );
	script_xref( name: "URL", value: "http://www.elastix.org/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/elastix", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	found = 0;
	if(concl = egrep( string: buf, pattern: "(>Elastix<|https?://www\\.elastix\\.(org|com))", icase: FALSE )){
		found++;
		concluded = chomp( concl );
	}
	if(concl = egrep( string: buf, pattern: "elastix_logo_mini\\.png.+elastix logo", icase: FALSE )){
		found++;
		if(concluded){
			concluded += "\n";
		}
		concluded += chomp( concl );
	}
	if(concl = egrep( string: buf, pattern: "<title>Elastix", icase: FALSE )){
		found++;
		if(concluded){
			concluded += "\n";
		}
		concluded += chomp( concl );
	}
	if(found > 1){
		set_kb_item( name: "elastix/detected", value: TRUE );
		set_kb_item( name: "elastix/http/detected", value: TRUE );
		concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		version = "unknown";
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Elastix Detection (HTTP)", runs_key: "unixoide" );
		register_and_report_cpe( app: "Elastix", ver: version, concluded: concluded, base: "cpe:/a:elastix:elastix:", expr: "([0-9.]+)", insloc: install, regPort: port, regService: "www", conclUrl: concl_url );
		exit( 0 );
	}
}
exit( 0 );

