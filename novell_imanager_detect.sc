if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100434" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Novell / NetIQ / Micro Focus iManager Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.novell.com/products/consoles/imanager/overview.html" );
	script_xref( name: "URL", value: "https://www.microfocus.com/products/open-enterprise-server/features/imanager-network-administration-tool/" );
	script_tag( name: "summary", value: "Detection of Novell / NetIQ / Micro Focus iManager.

  This host is running Novell / NetIQ / Micro Focus iManager, a Web-based administration console
  that provides customized access to network administration utilities and content from virtually any location." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
url = "/nps/servlet/webacc?taskId=dev.Empty&merge=fw.About";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(isnull( buf )){
	exit( 0 );
}
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "iManager" ) || ContainsString( buf, "<title>NetIQ Access Manager" ) )){
	if( ContainsString( buf, "NetIQ" ) ){
		appname = "NetIQ iManager";
		basecpe = "cpe:/a:netiq:imanager";
	}
	else {
		appname = "Novell iManager";
		basecpe = "cpe:/a:novell:imanager";
	}
	version = "unknown";
	url = "/nps/version.jsp";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	vers = eregmatch( string: buf, pattern: "([0-9.]+)", icase: TRUE );
	if( !isnull( vers[1] ) ){
		version = vers[1];
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	else {
		url = "/nps/version.properties";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		vers = eregmatch( string: buf, pattern: "version=([0-9.]+)", icase: TRUE );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			url = "/nps/UninstallerData/installvariables.properties";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			vers = eregmatch( string: buf, pattern: "PRODUCT_NAME=(NetIQ|Novell) iManager ([0-9.]+)", icase: TRUE );
			if(!isnull( vers[2] )){
				version = vers[2];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
	set_kb_item( name: "novellimanager/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: basecpe + ":" );
	if(!cpe){
		cpe = basecpe;
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: appname, version: version, install: "/", cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ), port: port );
}
exit( 0 );

