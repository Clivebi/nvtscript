if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105112" );
	script_version( "2021-03-08T08:30:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-08 08:30:01 +0000 (Mon, 08 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-11-11 10:04:39 +0100 (Tue, 11 Nov 2014)" );
	script_name( "Dropbear Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/dropbear_ssh/detected" );
	script_tag( name: "summary", value: "SSH based detection of Dropbear." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(banner && IsMatchRegexp( banner, "SSH.+dropbear" )){
	version = "unknown";
	install = port + "/tcp";
	vers = eregmatch( pattern: "SSH-.+dropbear[_-]([0-9.]+)", string: banner, icase: TRUE );
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "dropbear_ssh/ssh/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers[0] );
	set_kb_item( name: "dropbear_ssh/detected", value: TRUE );
	set_kb_item( name: "dropbear_ssh/ssh/detected", value: TRUE );
	set_kb_item( name: "dropbear_ssh/ssh/port", value: port );
}
exit( 0 );

