if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800165" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "evalSMSI Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the installed evalSMSI version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
evalSMSIPort = http_get_port( default: 80 );
if(!http_can_host_php( port: evalSMSIPort )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/evalsmsi", "/", http_cgi_dirs( port: evalSMSIPort ) ) {
	install = path;
	if(path == "/"){
		path = "";
	}
	sndReq = http_get( item: path + "/evalsmsi.php", port: evalSMSIPort );
	rcvRes = http_keepalive_send_recv( port: evalSMSIPort, data: sndReq );
	if(ContainsString( rcvRes, ">EvalSMSI" )){
		version = "unknown";
		evalSMSIVer = eregmatch( pattern: ">EvalSMSI version ([0-9.]+) ?--", string: rcvRes );
		if(evalSMSIVer[1] != NULL){
			version = evalSMSIver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + evalSMSIPort + "/evalSMSI", value: tmp_version );
		set_kb_item( name: "evalsmsi/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:myshell:evalsmsi:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:myshell:evalsmsi";
		}
		register_product( cpe: cpe, location: install, port: evalSMSIPort, service: "www" );
		log_message( data: build_detection_report( app: "Eval SMSI", version: version, install: install, cpe: cpe, concluded: evalSMSIVer[0] ), port: evalSMSIPort );
	}
}

