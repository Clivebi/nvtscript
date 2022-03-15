if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105531" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-01-27 10:22:48 +0100 (Wed, 27 Jan 2016)" );
	script_name( "Cisco show version" );
	script_tag( name: "summary", value: "This script execute 'show version' on the target and store the result in the KB for later use" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cisco/detected" );
	exit( 0 );
}
require("ssh_func.inc.sc");
if(!get_kb_item( "cisco/detected" )){
	exit( 0 );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
system = ssh_cmd( socket: sock, cmd: "show version\n", nosh: TRUE );
if(ContainsString( system, "Error getting tty" )){
	system = ssh_cmd( socket: sock, cmd: "show version\n", nosh: TRUE, pty: TRUE );
}
close( sock );
if(system){
	set_kb_item( name: "cisco/show_version", value: system );
}
exit( 0 );

