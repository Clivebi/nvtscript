if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900675" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Mutt Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Mutt.

  The script logs in via ssh, searches for executable 'mutt' and
  queries the found executables via command line option '-v'." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "mutt", sock: sock );
for executableFile in paths {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	muttVer = ssh_get_bin_version( full_prog_name: executableFile, sock: sock, version_argv: "-v", ver_pattern: "Mutt (([0-9.]+)([a-z])?)" );
	if(!isnull( muttVer[1] )){
		set_kb_item( name: "Mutt/Ver", value: muttVer[1] );
		set_kb_item( name: "mutt/detected", value: TRUE );
		register_and_report_cpe( app: "Mutt", ver: muttVer[1], concluded: muttVer[0], base: "cpe:/a:mutt:mutt:", expr: "^([0-9.]+)", insloc: executableFile, regPort: 0, regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

