if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900217" );
	script_version( "2021-08-11T09:39:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 09:39:10 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "IBM Db2 Detection (Linux/Unix SSH Login)" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of IBM Db2 Server." );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
port = kb_ssh_transport();
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
db2ls_res = ssh_cmd( socket: sock, cmd: "db2ls -a", timeout: 120 );
ssh_close_connection();
if(!db2ls_res || !ContainsString( db2ls_res, "Install Path" )){
	exit( 0 );
}
version = "unknown";
fix_pack = "unknown";
set_kb_item( name: "ibm/db2/detected", value: TRUE );
set_kb_item( name: "ibm/db2/ssh-login/port", value: port );
vers = eregmatch( pattern: " ([0-9.]+)", string: strstr( db2ls_res, "/" ) );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "ibm/db2/ssh-login/" + port + "/concluded", value: db2ls_res );
}
fp = eregmatch( pattern: " [0-9.]+[^0-9]+([0-9]+)", string: strstr( db2ls_res, "/" ) );
if(!isnull( fp[1] )){
	fix_pack = fp[1];
}
set_kb_item( name: "ibm/db2/ssh-login/" + port + "/version", value: version );
set_kb_item( name: "ibm/db2/ssh-login/" + port + "/fix_pack", value: fix_pack );
exit( 0 );

