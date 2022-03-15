if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106078" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-05-20 11:10:26 +0700 (Fri, 20 May 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Watchguard Fireware XTM Web UI Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.watchguard.com/products/fireware-xtm.asp" );
	script_tag( name: "summary", value: "Detection of Watchguard Fireware XTM Web UI

  The script sends a connection request to the server and attempts to detect Watchguard Fireware XTM Web UI" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, ">The <b>Fireware XTM Web UI from WatchGuard</b>" ) || ContainsString( res, "<title>Fireware XTM User Authentication</title>" ) || ContainsString( res, "/wgcgi.cgi?action=fw_logon" )){
	vers = "unknown";
	install = "/";
	set_kb_item( name: "www/" + port + "/watchguard_fireware", value: vers );
	set_kb_item( name: "watchguard_fireware/installed", value: TRUE );
	cpe = "cpe:/o:watchguard:fireware";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	os_register_and_report( os: "WatchGuard Fireware", cpe: cpe, banner_type: "HTTP(s) Login Page", port: port, desc: "Watchguard Fireware XTM Web UI Detection", runs_key: "unixoide" );
	log_message( data: build_detection_report( app: "Watchguard Fireware XTM OS", version: vers, install: install, cpe: cpe ), port: port );
}
exit( 0 );

