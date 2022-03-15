if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146147" );
	script_version( "2021-06-18T07:48:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-18 07:48:29 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-18 03:03:16 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "OpenLDAP Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of OpenLDAP." );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
soc = ssh_login_or_reuse_connection();
if(!soc){
	exit( 0 );
}
port = kb_ssh_transport();
paths = ssh_find_file( file_name: "/slapd$", sock: soc, useregex: TRUE );
for file in paths {
	version = "unknown";
	file = chomp( file );
	if(!file){
		continue;
	}
	res = ssh_cmd( socket: soc, cmd: file + " -V" );
	if(ContainsString( res, "OpenLDAP: slapd " )){
		vers = eregmatch( pattern: "OpenLDAP: slapd ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "openldap/detected", value: TRUE );
		set_kb_item( name: "openldap/ssh-login/detected", value: TRUE );
		set_kb_item( name: "openldap/ssh-login/" + port + "/installs", value: "0#---#" + file + "#---#" + version + "#---#" + res );
	}
}
exit( 0 );

