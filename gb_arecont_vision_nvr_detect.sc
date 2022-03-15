if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114050" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-21 15:38:32 +0100 (Fri, 21 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Arecont Vision NVR Detection" );
	script_tag( name: "summary", value: "Detection of Arecont Vision's IP camera software and their NVR.

  The script sends a connection request to the server and attempts to detect the web interface for Arecont Vision's IP cameras, as well as the NVR model." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://arecontvision.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/";
req = http_get_req( port: port, url: url, user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, "content='0; url=ErrBrowserNotSupported.htm'>" )){
	url = "/index.html";
	res = http_get_cache( port: port, item: url );
}
if(ContainsString( res, "var var_brand=\"Arecont Vision\";" ) || ContainsString( res, "alt=\"Arecont Vision logo\" src=" )){
	version = "unknown";
	model = "unknown";
	install = "/";
	req = http_get_req( port: port, url: "/models/all-cmd.js", add_headers: make_array( "Cookie", "Auto=1; Auth=Basic%20YZ%3D" ) );
	res = http_send_recv( port: port, data: req );
	mod = eregmatch( pattern: "WWW-Authenticate: Basic realm=\"([A-Za-z]{1,3}[0-9]{1,4})\"", string: res );
	if( !isnull( mod[1] ) ) {
		model = mod[1];
	}
	else {
		res = http_get_cache( port: port, item: "/get?model=releasename" );
		mod = eregmatch( pattern: "model=([A-Za-z0-9\\-]+)", string: res );
		if(!isnull( mod[1] )){
			model = mod[1];
		}
	}
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	cpe = "cpe:/h:arecont_vision:nvr:";
	set_kb_item( name: "arecont_vision/nvr/detected", value: TRUE );
	set_kb_item( name: "arecont_vision/nvr/" + port + "/detected", value: TRUE );
	set_kb_item( name: "arecont_vision/nvr/model", value: model );
	register_and_report_cpe( app: "Arecont Vision NVR", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www", conclUrl: conclUrl, extra: "Model: " + model + ", Version detection requires successful login." );
}
exit( 0 );

