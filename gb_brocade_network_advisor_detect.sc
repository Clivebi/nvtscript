if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106515" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-01-16 10:12:31 +0700 (Mon, 16 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Brocade Network Advisor Detection" );
	script_tag( name: "summary", value: "Detection of Brocade Network Advisor

  The script sends a HTTP connection request to the server and attempts to detect the presence of Brocade Network
  Advisor and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.brocade.com/de/products-services/network-management/brocade-network-advisor.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("url_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/login.xhtml" );
if(ContainsString( res, "<title>Network Advisor Login</title>" ) && ContainsString( res, "ui-menuitem-text\">About Network Advisor" )){
	version = "unknown";
	cookie = eregmatch( pattern: "Set-Cookie: (JSESSIONID=[^;]+)", string: res );
	if(!isnull( cookie[1] )){
		cookie = cookie[1];
	}
	viewstate = eregmatch( pattern: "javax.faces.ViewState(..)?\" value=\"([^\"]+)", string: res );
	if(!isnull( viewstate[2] )){
		viewstate = urlencode( str: viewstate[2] );
	}
	data = "javax.faces.partial.ajax=true&javax.faces.source=aboutDialog&javax.faces.partial.execute=aboutDialog&javax.faces.partial.render=aboutDialog&aboutDialog=aboutDialog&aboutDialog_contentLoad=true&loginForm=loginForm&loginForm%3Akey=&loginForm%3Avalue=&javax.faces.ViewState=" + viewstate;
	req = http_post_put_req( port: port, url: "/login.xhtml", data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8", "Cookie", cookie ) );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "Network Advisor ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "brocade_network_advisor/version", value: version );
	}
	set_kb_item( name: "brocade_network_advisor/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:brocade:network_advisor:" );
	if(!cpe){
		cpe = "cpe:/a:brocade:network_advisor";
	}
	register_product( cpe: cpe, location: "/", port: port );
	log_message( data: build_detection_report( app: "Brocade Network Advisor", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

