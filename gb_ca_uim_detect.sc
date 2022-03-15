if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106385" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-11-11 11:33:27 +0700 (Fri, 11 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "CA/Broadcom Unified Infrastructure Management (UIM) Server Detection" );
	script_tag( name: "summary", value: "Detection of CA/Broadcom Unified Infrastructure Management (UIM) Server

  The script sends a connection request to the server and attempts to detect the presence of CA/Broadcom Unified
  Infrastructure Management (UIM) Server and to extract its version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.broadcom.com/info/aiops/unified-infrastructure-management" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/uimhome", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	res = http_get_cache( port: port, item: url );
	if(ContainsString( res, "Welcome to UIM Server" ) && "UIM Server administration"){
		version = "unknown";
		conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		vers = eregmatch( pattern: "Welcome to UIM Server ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "ca/unified_infrastructure_management/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ca:unified_infrastructure_management:" );
		if(!cpe){
			cpe = "cpe:/a:ca:unified_infrastructure_management";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		cpe2 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:broadcom:unified_infrastructure_management:" );
		if(!cpe2){
			cpe2 = "cpe:/a:broadcom:unified_infrastructure_management";
		}
		register_product( cpe: cpe2, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "CA/Broadcom Unified Infrastructure Management", version: version, install: install, cpe: cpe + "\n               " + cpe2, concluded: vers[0], concludedUrl: conclurl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

