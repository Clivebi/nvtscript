if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800683" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DotNetNuke Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of DotNetNuke." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/dotnetduke", "/dnnarticle", "/cms", "/DotNetNuke", "/DotNetNuke Website", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/default.aspx", port: port );
	sndReq2 = http_get( item: dir + "/Install/InstallWizard.aspx", port: port );
	rcvRes2 = http_keepalive_send_recv( port: port, data: sndReq2 );
	sndReq3 = http_get( item: dir + "/DesktopModules/AuthenticationServices/OpenID/license.txt", port: port );
	rcvRes3 = http_keepalive_send_recv( port: port, data: sndReq3 );
	if(( IsMatchRegexp( rcvRes2, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes2, "DotNetNuke Installation Wizard" ) ) || ( IsMatchRegexp( rcvRes3, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes3, "DotNetNuke" ) && ContainsString( rcvRes3, "www.dotnetnuke.com" ) ) || ( IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "DotNetNuke" ) && ( ContainsString( rcvRes, "DesktopModules" ) || ContainsString( rcvRes, "dnnVariable" ) || ContainsString( rcvRes, "www.dotnetnuke.com" ) || ContainsString( rcvRes, "DNN_HTML" ) || ContainsString( rcvRes, "DotNetNukeAnonymous" ) ) ) || ( IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( rcvRes, "id=\"dnn_" ) && IsMatchRegexp( rcvRes, "class=\"DnnModule" ) )){
		version = "unknown";
		ver = eregmatch( pattern: "DNN ([0-9.]+)", string: rcvRes );
		if(ver[1] != NULL){
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/DotNetNuke", value: tmp_version );
		set_kb_item( name: "dotnetnuke/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:dotnetnuke:dotnetnuke:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:dotnetnuke:dotnetnuke";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Dot Net Nuke", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

