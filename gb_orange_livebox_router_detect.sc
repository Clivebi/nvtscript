if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114053" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-27 16:40:02 +0100 (Thu, 27 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Orange Livebox Router Detection" );
	script_tag( name: "summary", value: "Detection of Orange Livebox router.

  The script sends a connection request to the server and attempts to detect the web interface for Orange's Livebox router." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.arcadyan.com/home.aspx" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "var company=\"Arcadyan Inc.\";" ) && ContainsString( res, "var help_urlname=\"www.arcadyan.com/802\";" ) && ContainsString( res, "var urlname=\"www.arcadyan.com\";" )){
	version = "unknown";
	model = "unknown";
	install = "/";
	ver = eregmatch( pattern: "var firmware_ver='([0-9.A-Za-z]+)';", string: res );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "orange/livebox/version", value: version );
	}
	mod = eregmatch( pattern: "var product_name=\"Arcadyan ([a-zA-Z0-9]+)\";", string: res );
	if(!isnull( mod[1] )){
		model = mod[1];
		set_kb_item( name: "orange/livebox/model", value: model );
	}
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	cpe = "cpe:/h:orange:livebox:";
	set_kb_item( name: "orange/livebox/detected", value: TRUE );
	set_kb_item( name: "orange/livebox/" + port + "/detected", value: TRUE );
	register_and_report_cpe( app: "Orange Livebox Router", ver: version, base: cpe, expr: "^([0-9.A-Za-z]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "Model: " + model );
}
exit( 0 );

