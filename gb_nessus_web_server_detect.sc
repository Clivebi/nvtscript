if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801392" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Nessus Web Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8834 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running version of Nessus, Nessus Web Server/UI and the
  type of Nessus." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8834 );
url = "/feed";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( res, "<web_server_version>" ) || ContainsString( res, "<server_version>" ) || ContainsString( res, "<nessus_type>" )){
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	install = port + "/tcp";
	version = "unknown";
	versionWs = "unknown";
	type = "unknown";
	feed = "unknown";
	versionUi = "unknown";
	nessusWsVersion = eregmatch( pattern: "<web_server_version>([0-9.]+)", string: res );
	nessusVersion = eregmatch( pattern: "<server_version>([0-9.]+)", string: res );
	nessusType = eregmatch( pattern: "<nessus_type>([a-zA-Z ()]+)", string: res );
	nessusFeed = eregmatch( pattern: "<feed>([a-zA-Z ]+)", string: res );
	nessusUiVersion = eregmatch( pattern: "<nessus_ui_version>([0-9.]+)", string: res );
	if(nessusVersion[1]){
		version = nessusVersion[1];
	}
	if(nessusWsVersion[1]){
		versionWs = nessusWsVersion[1];
	}
	if(nessusType[1]){
		type = nessusType[1];
	}
	if(nessusFeed[1]){
		feed = nessusFeed[1];
	}
	if(nessusUiVersion[1]){
		versionUi = nessusUiVersion[1];
	}
	set_kb_item( name: "nessus/installed", value: TRUE );
	set_kb_item( name: "www/" + port + "/Nessus/Web/Server", value: versionWs );
	set_kb_item( name: "www/" + port + "/nessus", value: version );
	set_kb_item( name: "www/" + port + "/nessus_web_ui", value: versionUi );
	register_and_report_cpe( app: "Nessus", ver: version, concluded: nessusVersion[0] + "\n" + nessusWsVersion[0] + "\n" + nessusFeed[0] + "\n" + nessusType[0], base: "cpe:/a:tenable:nessus:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "Nessus Web Server version is: \"" + versionWs + "\"\n" + "Nessus type is: \"" + type + "\"\n" + "Nessus feed is: \"" + feed + "\"" );
	register_and_report_cpe( app: "Nessus Web UI", ver: versionUi, concluded: nessusUiVersion[0], base: "cpe:/a:tenable:web_ui:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl );
	exit( 0 );
}
url = "/server/properties";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && props = egrep( string: res, pattern: "^\\{\".*(nessus_type|nessus_ui_version|nessus_ui_build)\":\"", icase: TRUE )){
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	install = port + "/tcp";
	serverVersion = "unknown";
	serverBuild = "unknown";
	uiVersion = "unknown";
	uiBuild = "unknown";
	type = "unknown";
	nessusType = eregmatch( pattern: "nessus_type\":\"([^\",]+)", string: props );
	nessusServerVersion = eregmatch( pattern: "server_version\":\"([^\",]+)", string: props );
	nessusServerBuild = eregmatch( pattern: "server_build\":\"([^\",]+)", string: props );
	nessusUiVersion = eregmatch( pattern: "nessus_ui_version\":\"([^\",]+)", string: props );
	nessusUiBuild = eregmatch( pattern: "nessus_ui_build\":\"([^\",]+)", string: props );
	if(nessusServerVersion[1]){
		serverVersion = nessusServerVersion[1];
	}
	if(nessusServerBuild[1]){
		serverBuild = nessusServerBuild[1];
	}
	if(nessusUiVersion[1]){
		uiVersion = nessusUiVersion[1];
	}
	if(nessusUiBuild[1]){
		uiBuild = nessusUiBuild[1];
	}
	if( nessusType[1] ){
		type = nessusType[1];
		app = nessusType[1];
		uiApp = nessusType[1] + " Web UI";
	}
	else {
		app = "Nessus";
		uiApp = "Nessus Web UI";
	}
	set_kb_item( name: "nessus/installed", value: TRUE );
	set_kb_item( name: "www/" + port + "/nessus/server_version", value: serverVersion );
	set_kb_item( name: "www/" + port + "/nessus/server_build", value: serverBuild );
	set_kb_item( name: "www/" + port + "/nessus/web_ui_version", value: uiVersion );
	set_kb_item( name: "www/" + port + "/nessus/web_ui_build", value: uiBuild );
	set_kb_item( name: "www/" + port + "/nessus/type", value: type );
	server_cpe = build_cpe( value: serverVersion, exp: "^([0-9.]+)", base: "cpe:/a:tenable:nessus:" );
	if(!server_cpe){
		server_cpe = "cpe:/a:tenable:nessus";
	}
	ui_cpe = build_cpe( value: uiVersion, exp: "^([0-9.]+)", base: "cpe:/a:tenable:web_ui:" );
	if(!ui_cpe){
		ui_cpe = "cpe:/a:tenable:web_ui";
	}
	register_product( cpe: server_cpe, location: install, port: port, service: "www" );
	register_product( cpe: ui_cpe, location: install, port: port, service: "www" );
	report = build_detection_report( app: app, version: serverVersion, install: install, cpe: server_cpe );
	report += "\n\n";
	report += build_detection_report( app: uiApp, version: uiVersion, install: install, cpe: ui_cpe );
	report += "\n\nConcluded from version/product identification result:\n" + props;
	report += "\nConcluded from version/product identification location:\n" + conclUrl;
	log_message( port: port, data: report );
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(concl = egrep( pattern: "Server: NessusWWW", string: banner, icase: TRUE )){
	version = "unknown";
	install = port + "/tcp";
	server_cpe = "cpe:/a:tenable:nessus";
	ui_cpe = "cpe:/a:tenable:web_ui";
	set_kb_item( name: "nessus/installed", value: TRUE );
	set_kb_item( name: "www/" + port + "/nessus/server_version", value: version );
	set_kb_item( name: "www/" + port + "/nessus/web_ui_version", value: version );
	register_product( cpe: server_cpe, location: install, port: port, service: "www" );
	register_product( cpe: ui_cpe, location: install, port: port, service: "www" );
	report = build_detection_report( app: "Nessus", version: version, install: install, cpe: server_cpe );
	report += "\n\n";
	report += build_detection_report( app: "Nessus Web UI", version: version, install: install, cpe: ui_cpe );
	report += "\n\nConcluded from version/product identification result:\n" + concl;
	log_message( port: port, data: report );
}
exit( 0 );

