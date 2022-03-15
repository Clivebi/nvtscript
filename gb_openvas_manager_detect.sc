if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103825" );
	script_version( "2021-05-10T09:35:39+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 09:35:39 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2013-11-08 12:24:10 +0100 (Fri, 08 Nov 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OpenVAS / Greenbone Vulnerability Manager Detection (OMP/GMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service3.sc" );
	script_require_ports( "Services/omp_gmp", 9390 );
	script_tag( name: "summary", value: "OpenVAS Management Protocol (OMP) / Greenbone Management
  Protocol (GMP) based detection of an OpenVAS Manager (openvasmd) or Greebone Vulnerability Manager
  (gmvd)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = service_get_port( default: 9390, proto: "omp_gmp" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = "<get_version/>";
send( socket: soc, data: req + "\r\n" );
res = recv( socket: soc, length: 256 );
close( soc );
if(!res || !IsMatchRegexp( res, "<get_version_response.+</get_version_response>" )){
	exit( 0 );
}
set_kb_item( name: "openvasmd_gvmd/detected", value: TRUE );
set_kb_item( name: "openvas_gvm/framework_component/detected", value: TRUE );
manager_version = "unknown";
proto_version = "unknown";
install = port + "/tcp";
proto = "omp_gmp";
app_name = "OpenVAS / Greenbone Vulnerability Manager";
base_cpe = "cpe:/a:greenbone:greenbone_vulnerability_manager";
concluded = " - OMP/GMP protocol version request:  " + req + "\n";
concluded += " - OMP/GMP protocol version response: " + res;
ver = eregmatch( pattern: "<get_version_response.+<version>([0-9.]+)</version>", string: res );
if(ver[1]){
	proto_version = ver[1];
	manager_version = proto_version;
}
if( version_is_less( version: proto_version, test_version: "8.0" ) ){
	app_name = "OpenVAS Manager";
	base_cpe = "cpe:/a:openvas:openvas_manager";
	concluded = " - OMP protocol version request:  " + req + "\n";
	concluded += " - OMP protocol version response: " + ver[0];
}
else {
	app_name = "Greenbone Vulnerability Manager";
	base_cpe = "cpe:/a:greenbone:greenbone_vulnerability_manager";
	concluded = " - GMP protocol version request:  " + req + "\n";
	concluded += " - GMP protocol version response: " + ver[0];
}
cpe = build_cpe( value: manager_version, exp: "^([0-9.]+)", base: base_cpe + ":" );
if(!cpe){
	cpe = base_cpe;
}
service_register( port: port, proto: proto );
register_product( cpe: cpe, location: install, port: port, service: proto );
os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", port: port, desc: "OpenVAS / Greenbone Vulnerability Manager Detection (OMP/GMP)", runs_key: "unixoide" );
log_message( data: build_detection_report( app: app_name, version: manager_version, install: install, cpe: cpe, concluded: concluded ), port: port );
exit( 0 );

