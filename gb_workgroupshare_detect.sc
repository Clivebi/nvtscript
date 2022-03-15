if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100518" );
	script_version( "2020-11-11T10:32:17+0000" );
	script_tag( name: "last_modification", value: "2020-11-11 10:32:17 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-03-05 14:01:46 +0100 (Fri, 05 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "WorkgroupShare Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service_spontaneous.sc" );
	script_require_ports( "Services/workgroupshare", 8100 );
	script_tag( name: "summary", value: "Checks if WorkgroupShare Server is running on the remote host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 8100, proto: "workgroupshare" );
if(!banner = get_kb_item( "workgroupshare/" + port + "/banner" )){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: "\\n" );
	banner = recv( socket: soc, length: 512 );
	if(!banner){
		exit( 0 );
	}
}
if(concl = egrep( pattern: "^OK WorkgroupShare.+server ready", string: banner, icase: FALSE )){
	concl = chomp( concl );
	version = "unknown";
	install = port + "/tcp";
	vers = eregmatch( pattern: "WorkgroupShare ([0-9.]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	service_register( port: port, proto: "workgroupshare" );
	set_kb_item( name: "workgroupshare/detected", value: TRUE );
	set_kb_item( name: "workgroupshare/" + port + "/detected", value: TRUE );
	set_kb_item( name: "workgroupshare/" + port + "/version", value: version );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:workgroupshare:" );
	if(!cpe){
		cpe = "cpe:/a:ipswitch:workgroupshare";
	}
	register_product( cpe: cpe, location: install, port: port, service: "workgroupshare" );
	log_message( data: build_detection_report( app: "WorkgroupShare Server", version: version, install: install, cpe: cpe, concluded: concl ), port: port );
}
exit( 0 );

