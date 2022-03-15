if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108351" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NetEx HyperIP Detection (SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "hyperip/ssh-login/show_version_or_uname" );
	script_tag( name: "summary", value: "SSH login-based detection of a NetEx HyperIP virtual appliance." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "hyperip/ssh-login/show_version_or_uname" )){
	exit( 0 );
}
version = "unknown";
port = get_kb_item( "hyperip/ssh-login/port" );
show_version = get_kb_item( "hyperip/ssh-login/" + port + "/show_version" );
uname = get_kb_item( "hyperip/ssh-login/" + port + "/uname" );
if(!show_version && !uname){
	exit( 0 );
}
vers = eregmatch( pattern: "Product Version([^\\n]+)HyperIP ([0-9.]+)", string: show_version );
if( vers[2] ){
	version = vers[2];
	set_kb_item( name: "hyperip/ssh-login/" + port + "/concluded", value: vers[0] + " from 'showVersion' command" );
}
else {
	set_kb_item( name: "hyperip/ssh-login/" + port + "/concluded", value: uname );
}
set_kb_item( name: "hyperip/detected", value: TRUE );
set_kb_item( name: "hyperip/ssh-login/detected", value: TRUE );
set_kb_item( name: "hyperip/ssh-login/" + port + "/version", value: version );
exit( 0 );

