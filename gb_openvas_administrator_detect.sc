if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103826" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-11-08 12:28:10 +0100 (Fri, 08 Nov 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OpenVAS Administrator Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service3.sc" );
	script_require_ports( "Services/oap", 9393 );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  determine if it is a OpenVAS Administrator service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = service_get_port( default: 9393, proto: "oap" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
vt_strings = get_vt_strings();
req = "<" + vt_strings["lowercase"] + "/>";
send( socket: soc, data: req + "\r\n" );
res = recv( socket: soc, length: 256 );
close( soc );
if(ContainsString( res, "oap_response" ) && ContainsString( res, "GET_VERSION" )){
	set_kb_item( name: "openvas_administrator/detected", value: TRUE );
	set_kb_item( name: "openvas_gvm/framework_component/detected", value: TRUE );
	version = "unknown";
	cpe = "cpe:/a:openvas:openvas_administrator";
	install = port + "/tcp";
	concluded = "OAP protocol probe '" + req + "', response: " + res;
	service_register( port: port, proto: "oap" );
	register_product( cpe: cpe, location: install, port: port, proto: "oap" );
	log_message( data: build_detection_report( app: "OpenVAS Administrator", version: version, install: install, cpe: cpe, concluded: concluded ), port: port );
}
exit( 0 );

