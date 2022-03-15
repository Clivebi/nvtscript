if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900569" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Ruby Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Ruby." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/ruby$", useregex: TRUE, sock: sock );
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-v", ver_pattern: "ruby ([0-9.]+)((p| ?patchlevel)([0-9]+))?" );
	if(!isnull( vers[1] )){
		version = vers[1];
		if(!isnull( vers[2] )){
			version += "." + vers[4];
		}
		set_kb_item( name: "ruby/detected", value: TRUE );
		set_kb_item( name: "ruby/ssh-login/detected", value: TRUE );
		set_kb_item( name: "ruby/ssh-login/port", value: "22" );
		set_kb_item( name: "ruby/ssh-login/22/install", value: "22#---#" + bin + "#---#" + version + "#---#" + vers[0] );
	}
}
ssh_close_connection();
exit( 0 );

