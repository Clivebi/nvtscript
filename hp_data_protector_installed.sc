if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19601" );
	script_version( "2021-08-09T07:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 07:01:45 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Micro Focus / HP / HPE (OpenView Storage) Data Protector Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 Josh Zlatin-Amishav" );
	script_family( "Product detection" );
	script_require_ports( "Services/hp_dataprotector", 5555 );
	script_dependencies( "find_service1.sc", "find_service2.sc" );
	script_tag( name: "summary", value: "Detection of Mirco Focus / HP / HPE (OpenView Storage) Data
  Protector.

  The script sends a connection request to the Mirco Focus / HP / HPE (OpenView Storage) Data
  Protector and attempts to extract the version number from the reply." );
	script_xref( name: "URL", value: "https://www.microfocus.com/en-us/products/data-protector-backup-recovery-software/overview" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = service_get_port( default: 5555, proto: "hp_dataprotector" );
if(!banner = get_kb_item( "hp_dataprotector/" + port + "/banner" )){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	banner = recv( socket: soc, length: 4096, timeout: 20 );
	close( soc );
}
if(banner && IsMatchRegexp( banner, "^(Micro Focus|HPE?) (OpenView Storage )?Data Protector" )){
	version = "unknown";
	build = "unknown";
	install = "/";
	vers = eregmatch( pattern: "Data Protector ([^:]+)", string: banner );
	if(vers[1]){
		version = vers[1];
	}
	bld = eregmatch( pattern: "internal build ([^,]+)", string: banner );
	if(bld[1]){
		build = bld[1];
	}
	service_register( port: port, proto: "hp_dataprotector" );
	set_kb_item( name: "microfocus/data_protector/detected", value: TRUE );
	set_kb_item( name: "microfocus/data_protector/" + port + "/build", value: build );
	cpe1 = build_cpe( value: version, exp: "^[a-zA-Z]\\.([0-9.]+)", base: "cpe:/a:hp:data_protector:" );
	cpe2 = build_cpe( value: version, exp: "^[a-zA-Z]\\.([0-9.]+)", base: "cpe:/a:hpe:data_protector:" );
	cpe3 = build_cpe( value: version, exp: "^[a-zA-Z]\\.([0-9.]+)", base: "cpe:/a:microfocus:data_protector:" );
	if(!cpe1){
		cpe1 = "cpe:/a:hp:data_protector";
		cpe2 = "cpe:/a:hpe:data_protector";
		cpe3 = "cpe:/a:microfocus:data_protector";
	}
	register_product( cpe: cpe1, location: install, port: port, service: "hp_dataprotector" );
	register_product( cpe: cpe2, location: install, port: port, service: "hp_dataprotector" );
	register_product( cpe: cpe3, location: install, port: port, service: "hp_dataprotector" );
	log_message( data: build_detection_report( app: "Micro Focus / HP / HPE (OpenView Storage) Data Protector", version: version, build: build, install: install, cpe: cpe3, concluded: chomp( banner ) ), port: port );
}
exit( 0 );

