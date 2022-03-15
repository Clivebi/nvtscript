if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108548" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-12 08:27:22 +0100 (Tue, 12 Feb 2019)" );
	script_name( "MikroTik RouterOS Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/mikrotik/routeros/detected" );
	script_tag( name: "summary", value: "Detection of MikroTik RouterOS via SSH.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(!banner || !ContainsString( banner, "SSH-2.0-ROSSSH" )){
	exit( 0 );
}
version = "unknown";
install = port + "/tcp";
set_kb_item( name: "mikrotik/detected", value: TRUE );
set_kb_item( name: "mikrotik/ssh/detected", value: TRUE );
set_kb_item( name: "mikrotik/ssh/" + port + "/concluded", value: banner );
set_kb_item( name: "mikrotik/ssh/port", value: port );
set_kb_item( name: "mikrotik/ssh/" + port + "/version", value: version );
exit( 0 );

