if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800633" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Irssi Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Irssi." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
irrsi_sock = ssh_login_or_reuse_connection();
if(!irrsi_sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "irssi", sock: irrsi_sock );
for irssi_bin in paths {
	irssi_bin = chomp( irssi_bin );
	if(!irssi_bin){
		continue;
	}
	irssi_ver = ssh_get_bin_version( full_prog_name: irssi_bin, sock: irrsi_sock, version_argv: "--version", ver_pattern: "irssi ([0-9.]+)" );
	if(irssi_ver[1]){
		vers = irssi_ver[1];
		set_kb_item( name: "irssi/detected", value: TRUE );
		set_kb_item( name: "Irssi/Lin/Ver", value: vers );
		register_and_report_cpe( app: "irssi", ver: vers, base: "cpe:/a:irssi:irssi:", expr: "([0-9.]+)", regPort: 0, insloc: irssi_bin, concluded: irssi_ver[0], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

