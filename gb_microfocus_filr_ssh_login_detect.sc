if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105824" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-07-25 16:02:26 +0200 (Mon, 25 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Micro Focus (Novell) Filr Detection (SSH Login)" );
	script_tag( name: "summary", value: "SSH login-based detection of Micro Focus (Novell) Filr." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "filr/ssh/rls" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!rls = get_kb_item( "filr/ssh/rls" )){
	exit( 0 );
}
if(!ContainsString( rls, "Filr" )){
	exit( 0 );
}
port = get_kb_item( "filr/ssh/port" );
version = "unknown";
set_kb_item( name: "microfocus/filr/detected", value: TRUE );
set_kb_item( name: "microfocus/filr/ssh-login/port", value: port );
set_kb_item( name: "microfocus/filr/ssh-login/" + port + "/concluded", value: chomp( rls ) );
vers = eregmatch( pattern: "version=([0-9.]+)", string: rls );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "microfocus/filr/ssh-login/" + port + "/version", value: version );
exit( 0 );

