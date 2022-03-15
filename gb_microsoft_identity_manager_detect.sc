if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140818" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-27 14:00:04 +0700 (Tue, 27 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Microsoft Identity Manager Detection" );
	script_tag( name: "summary", value: "Detection of Microsoft Identity Manager.

The script sends a connection request to the server and attempts to detect Microsoft Identity Manager and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/cloud-platform/microsoft-identity-manager" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
url = "/About.aspx";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "About Microsoft Identity Manager" ) && ContainsString( res, "WebForm_AutoFocus" )){
	version = "unknown";
	vers = eregmatch( pattern: "\"aboutVersionRowText\">Version ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
	}
	set_kb_item( name: "microsoft_identity_manager/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:identity_manager:" );
	if(!cpe){
		cpe = "cpe:/a:microsoft:identity_manager";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Microsoft Identity Manager", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

