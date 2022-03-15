if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108350" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NetEx HyperIP Detection (SSH-Banner)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/login_banner/available" );
	script_tag( name: "summary", value: "This script performs SSH banner based detection of a NetEx HyperIP
  virtual appliance." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_login_banner( port: port );
if(!banner || !egrep( pattern: "^HyperIP", string: banner, icase: FALSE )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "HyperIP ([0-9.]+)", string: banner );
if(vers[1]){
	version = vers[1];
	set_kb_item( name: "hyperip/ssh-banner/" + port + "/concluded", value: vers[0] );
}
set_kb_item( name: "hyperip/detected", value: TRUE );
set_kb_item( name: "hyperip/ssh-banner/detected", value: TRUE );
set_kb_item( name: "hyperip/ssh-banner/port", value: port );
set_kb_item( name: "hyperip/ssh-banner/" + port + "/version", value: version );
exit( 0 );

