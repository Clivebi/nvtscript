if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800688" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IkiWiki Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of IkiWiki and
  sets the specific KB entries." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
ssh_port = ssh_get_port( default: 22 );
paths = ssh_find_bin( prog_name: "ikiwiki", sock: sock );
for ikiwikibin in paths {
	ikiwikibin = chomp( ikiwikibin );
	if(!ikiwikibin){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: ikiwikibin, sock: sock, version_argv: "--version", ver_pattern: "ikiwiki version ([0-9.]+)" );
	if(vers[1]){
		set_kb_item( name: "ikiwiki/detected", value: TRUE );
		set_kb_item( name: "ikiwiki/ssh/detected", value: TRUE );
		version = vers[1];
		set_kb_item( name: "ikiwiki/ssh/" + ssh_port + "/concluded", value: vers[0] );
		set_kb_item( name: "ikiwiki/ssh/port", value: ssh_port );
		set_kb_item( name: "ikiwiki/ssh/" + ssh_port + "/version", value: version );
		set_kb_item( name: "ikiwiki/ssh/" + ssh_port + "/location", value: chomp( ikiwikibin ) );
		break;
	}
}
ssh_close_connection();
exit( 0 );

