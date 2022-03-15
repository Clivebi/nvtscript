if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141032" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-26 11:30:45 +0700 (Thu, 26 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Draytek VigorACS Detection" );
	script_tag( name: "summary", value: "Detection of Draytek VigorACS.

  The script sends a connection request to the server and attempts to detect Draytek VigorACS and to extract its
  version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.draytek.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
for url in make_list( "/web/",
	 "/web/ACS.html" ) {
	res = http_get_cache( port: port, item: url );
	if(!ContainsString( res, "<title>VigorACS Central Management System</title>" ) && !ContainsString( res, "<title>VigorACS</title>" )){
		continue;
	}
	version = "unknown";
	vers = eregmatch( pattern: "acsVersion=\"([^\"]+)\"", string: res );
	if( !isnull( vers[1] ) ){
		version = vers[1];
		concUrl = url;
	}
	else {
		p_url = "/ACSServer/Html5Servlet";
		data = "{\"act\":\"AboutVigorACS\",\"action\":\"version\",\"actionType\":1}";
		req = http_post_put_req( port: port, url: p_url, data: data, add_headers: make_array( "Content-Type", "application/json" ) );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "\\{\"version\":\"([^\"]+)\"\\}", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = p_url;
		}
	}
	set_kb_item( name: "draytek_vigoracs/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9a-z._]+)", base: "cpe:/a:draytek:vigoracs:" );
	if(!cpe){
		cpe = "cpe:/a:draytek:vigoracs";
	}
	register_product( cpe: cpe, location: "/web", port: port );
	log_message( data: build_detection_report( app: "Draytek VigorACS", version: version, install: "/web", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

