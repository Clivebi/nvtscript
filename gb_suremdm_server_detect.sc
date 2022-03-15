if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141987" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-12 15:35:57 +0700 (Tue, 12 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SureMDM Server Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of SureMDM Server.

  The script sends a connection request to the server and attempts to detect SureMDM Server and to extract its
  version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.42gears.com/products/suremdm-home/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/suremdm", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/console/" );
	if(ContainsString( res, "SureMDM : Login" ) && ContainsString( res, "DATABASECHECK" )){
		version = "unknown";
		url = dir + "/console/browserservice.aspx/GetVersions";
		headers = make_array( "Content-Type", "application/json; charset=utf-8", "X-Requested-With", "XMLHttpRequest", "ApiKey", "apiKey" );
		data = "{}";
		req = http_post_put_req( port: port, url: url, data: data, add_headers: headers );
		versres = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		vers = eregmatch( pattern: "\"sf\":\"([0-9.]+)\"", string: versres );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = url;
		}
		set_kb_item( name: "suremdm/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:42gears:suremdm:" );
		if(!cpe){
			cpe = "cpe:/a:42gears:suremdm";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SureMDM", version: version, install: install, cpe: cpe, concluded: versres, concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

