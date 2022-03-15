if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141339" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-01 12:09:01 +0700 (Wed, 01 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Huawei SoftCo Detection (telnet)" );
	script_tag( name: "summary", value: "Detection of Huawei SoftCo.

  The script sends a telnet connection request to the device and attempts to detect the presence of Huawei SoftCo
  and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/huawei/softco/detected" );
	script_xref( name: "URL", value: "https://www.huawei.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !IsMatchRegexp( banner, "SoftCo OS" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "SoftCo OS (V[^ ]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
}
mod = eregmatch( pattern: "on SoftCo([0-9]+)", string: banner );
if(!isnull( mod[1] )){
	model = mod[1];
	set_kb_item( name: "huawei_softco/model", value: model );
}
set_kb_item( name: "huawei_softco/detected", value: TRUE );
cpe = build_cpe( value: version, exp: "^(V[0-9A-Za-z]+)", base: "cpe:/h:huawei:softco:" );
if(!cpe){
	cpe = "cpe:/h:huawei:softco";
}
register_product( cpe: cpe, location: port + "/tcp", port: port, service: "telnet" );
log_message( data: build_detection_report( app: "Huawei SoftCo " + model, version: version, install: port + "/tcp", cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

