if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113326" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-22 14:43:33 +0100 (Tue, 22 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "DomainMOD Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether DomainMOD is present on
  the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://domainmod.org/" );
	script_xref( name: "URL", value: "https://github.com/domainmod" );
	exit( 0 );
}
CPE = "cpe:/a:domainmod:domainmod:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for location in nasl_make_list_unique( "/", "/domainmod", http_cgi_dirs( port: port ) ) {
	dir = location;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/CHANGELOG";
	buf = http_get_cache( item: url, port: port );
	if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf, "DomainMod CHANGELOG" )){
		set_kb_item( name: "domainmod/detected", value: TRUE );
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "v([0-9.]+)" );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		register_and_report_cpe( app: "DomainMOD", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: location, regPort: port, regService: "www", conclUrl: conclUrl );
		continue;
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "<title>DomainMOD</title>" )){
		set_kb_item( name: "domainmod/detected", value: TRUE );
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		version = "unknown";
		url = dir + "/version.txt";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		ver = eregmatch( string: buf, pattern: "^([0-9.]+)" );
		if(!isnull( ver[1] )){
			version = ver[1];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		register_and_report_cpe( app: "DomainMOD", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: location, regPort: port, regService: "www", conclUrl: conclUrl );
	}
}
exit( 0 );

