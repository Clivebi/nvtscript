if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103628" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-12-27 11:43:24 +0100 (Thu, 27 Dec 2012)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apple Mobile Device Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "secpod_open_tcp_ports.sc" );
	script_require_ports( 62078 );
	script_mandatory_keys( "TCP/PORTS" );
	script_tag( name: "summary", value: "Detection of Apple Mobile Devices.
  The script checks if port 62078/tcp is the only open port. If so, cpe:/o:apple:iphone_os is registered." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!get_port_state( 62078 )){
	exit( 0 );
}
ports = tcp_get_all_ports();
if(!ports){
	exit( 0 );
}
open_ports_count = max_index( make_list( ports ) );
if(open_ports_count > 1){
	exit( 0 );
}
for port in ports {
	if(port != "62078"){
		exit( 0 );
	}
}
os_register_and_report( os: "Apple iOS", cpe: "cpe:/o:apple:iphone_os", desc: "Apple Mobile Device Detection", runs_key: "unixoide" );
log_message( data: "The remote Host seems to be an Apple Device because port 62078 is the only open tcp port." );
exit( 0 );

