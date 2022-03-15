if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807076" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-01 14:45:32 +0530 (Tue, 01 Mar 2016)" );
	script_name( "GE SNMP/Web Interface Adapter Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/ge/snmp_web_iface_adapter/detected" );
	script_tag( name: "summary", value: "Detection of installed version
  of SNMP/Web Adapter.

  The script performs Telnet based detection of SNMP/Web Adapter" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(banner && IsMatchRegexp( banner, "GE.*SNMP/Web Interface" ) && ContainsString( banner, "UPS" )){
	version = "unknown";
	install = "/";
	ver = eregmatch( pattern: "SNMP/Web Interface Ver.([0-9.]+)", string: banner );
	if(ver[1]){
		version = ver[1];
	}
	set_kb_item( name: "SNMP/Web/Adapter/telnet/version", value: version );
	set_kb_item( name: "SNMP/Web/Adapter/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ge:ups_snmp_web_adapter_firmware:" );
	if(!cpe){
		cpe = "cpe:/a:ge:ups_snmp_web_adapter_firmware";
	}
	register_product( cpe: cpe, location: install, port: port, service: "telnet" );
	log_message( data: build_detection_report( app: "SNMP/Web Adapter", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
}
exit( 0 );

