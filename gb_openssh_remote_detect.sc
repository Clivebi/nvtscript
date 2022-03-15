if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108576" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-16 12:08:23 +0000 (Thu, 16 May 2019)" );
	script_name( "OpenSSH Detection (Remote)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/openssh/detected" );
	script_tag( name: "summary", value: "The script sends a connection request to the server
  and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(banner && ContainsString( banner, "OpenSSH" )){
	set_kb_item( name: "openssh/detected", value: TRUE );
	install = port + "/tcp";
	version = "unknown";
	concluded = banner;
	vers = eregmatch( pattern: "SSH.+OpenSSH[_ ](for_Windows_)?([.a-zA-Z0-9]+)[- ]?.*", string: banner );
	if(vers[2]){
		version = vers[2];
		concluded = vers[0];
	}
	set_kb_item( name: "openssh/ssh/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + concluded + "#---#Server" );
	set_kb_item( name: "openssh/detected", value: TRUE );
	set_kb_item( name: "openssh/ssh/detected", value: TRUE );
	set_kb_item( name: "openssh/ssh/port", value: port );
}
exit( 0 );

