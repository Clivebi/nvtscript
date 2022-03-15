if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901025" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Dovecot Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Dovecot." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "dovecot", sock: sock );
for dovecotbin in paths {
	dovecotbin = chomp( dovecotbin );
	if(!dovecotbin){
		continue;
	}
	dovecotVer = ssh_get_bin_version( full_prog_name: dovecotbin, sock: sock, version_argv: "--version", ver_pattern: "^([0-9.]{4,}(rc[0-9]+)?)\\s*(\\([^)]+\\))?" );
	if(!isnull( dovecotVer[1] )){
		set_kb_item( name: "dovecot/detected", value: TRUE );
		set_kb_item( name: "dovecot/ssh-login/detected", value: TRUE );
		set_kb_item( name: "dovecot/detection-info", value: "SSH login#--#ssh-login#--#0#--#" + dovecotbin + "#--#" + dovecotVer[1] + "#--#" + dovecotVer[0] );
	}
}
ssh_close_connection();
exit( 0 );

