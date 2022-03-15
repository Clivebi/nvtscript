if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111034" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-08-31 18:00:00 +0200 (Mon, 31 Aug 2015)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sphinx search server Detection" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "find_service1.sc" );
	script_require_ports( "Services/sphinxql", 9306, "Services/sphinxapi", 9312 );
	script_tag( name: "summary", value: "The script checks the presence of a Sphinx search server
  and sets the version in the kb." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("dump.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
ports = service_get_ports( default_port_list: make_list( 9306 ), proto: "sphinxql" );
for port in ports {
	if(!banner = get_kb_item( "sphinxsearch/" + port + "/sphinxql/banner" )){
		soc = open_sock_tcp( port );
		if(!soc){
			continue;
		}
		send( socket: soc, data: "TEST\\r\\n" );
		buf = recv( socket: soc, length: 64 );
		close( soc );
		if(!buf){
			continue;
		}
		banner = bin2string( ddata: buf, noprint_replacement: " " );
		if(!banner){
			continue;
		}
	}
	if(version = eregmatch( string: banner, pattern: "^.\\s{4}([0-9.]+)(-(id[0-9]+-)?release \\([0-9a-z-]+\\)| [0-9a-z]+@[0-9a-z]+ release)" )){
		replace_kb_item( name: "sphinxsearch/" + port + "/sphinxql/banner", value: banner );
		install = port + "/tcp";
		service_register( port: port, proto: "sphinxql" );
		set_kb_item( name: "sphinxsearch/detected", value: TRUE );
		set_kb_item( name: "sphinxsearch/noauth", value: TRUE );
		set_kb_item( name: "sphinxsearch/" + port + "/detected", value: TRUE );
		set_kb_item( name: "sphinxsearch/" + port + "/noauth", value: TRUE );
		set_kb_item( name: "sphinxsearch/" + port + "/version", value: version[1] );
		cpe = build_cpe( value: version[1], exp: "^([0-9.]+)", base: "cpe:/a:sphinxsearch:sphinxsearch:" );
		if(!cpe){
			cpe = "cpe:/a:sphinxsearch:sphinxsearch";
		}
		register_product( cpe: cpe, location: install, port: port, service: "sphinxql" );
		log_message( data: build_detection_report( app: "Sphinx search server", version: version[1], install: install, cpe: cpe, concluded: version[0] ), port: port );
	}
}
port = service_get_port( default: 9312, proto: "sphinxapi" );
if(!banner = get_kb_item( "sphinxsearch/" + port + "/sphinxapi/banner" )){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: "TEST\\r\\n\\r\\n" );
	buf = recv( socket: soc, length: 64 );
	close( soc );
	if(!buf){
		exit( 0 );
	}
	banner = bin2string( ddata: buf, noprint_replacement: " " );
	if(!banner){
		exit( 0 );
	}
}
if(banner = egrep( string: banner, pattern: "invalid command \\(code=([0-9]+), len=([0-9]+)\\)" )){
	replace_kb_item( name: "sphinxsearch/" + port + "/sphinxapi/banner", value: banner );
	version = "unknown";
	install = port + "/tcp";
	service_register( port: port, proto: "sphinxapi" );
	set_kb_item( name: "sphinxsearch/detected", value: TRUE );
	set_kb_item( name: "sphinxsearch/noauth", value: TRUE );
	set_kb_item( name: "sphinxsearch/" + port + "/detected", value: TRUE );
	set_kb_item( name: "sphinxsearch/" + port + "/noauth", value: TRUE );
	set_kb_item( name: "sphinxsearch/" + port + "/version", value: version );
	cpe = "cpe:/a:sphinxsearch:sphinxsearch";
	register_product( cpe: cpe, location: install, port: port, service: "sphinxapi" );
	log_message( data: build_detection_report( app: "Sphinx search server", version: version, install: install, cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

