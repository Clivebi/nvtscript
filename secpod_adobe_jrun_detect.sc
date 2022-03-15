if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900822" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sun Adobe JRun Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Adobe JRun." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
jrunPort = http_get_port( default: 8000 );
rcvRes = http_get_cache( item: "/", port: jrunPort );
if(egrep( pattern: "Server: JRun Web Server", string: rcvRes ) && egrep( pattern: "^HTTP/.* 200 OK", string: rcvRes )){
	jrunVer = eregmatch( pattern: ">Version ([0-9.]+)", string: rcvRes );
	if(jrunVer[1] != NULL){
		set_kb_item( name: "/Adobe/JRun/Ver", value: jrunVer[1] );
		log_message( data: "Adobe JRun version " + jrunVer[1] + " was detected on the host" );
		cpe = build_cpe( value: jrunVer[1], exp: "^([0-9.]+)", base: "cpe:/a:adobe:jrun:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe );
		}
	}
}

