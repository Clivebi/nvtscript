if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813269" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-30 16:57:40 +0530 (Mon, 30 Jul 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "TeamViewer Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of TeamViewer.

  The script logs in via SSH, searches for the executable 'TeamViewer.' and
  queries the found executables via the command line option '--version'" );
	script_category( ACT_GATHER_INFO );
	script_xref( name: "URL", value: "https://www.teamviewer.com/en" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
binaries = ssh_find_file( file_name: "/teamviewer$", useregex: TRUE, sock: sock );
for binary in binaries {
	binary = chomp( binary );
	if(!binary){
		continue;
	}
	teamViwVer = ssh_get_bin_version( full_prog_name: binary, sock: sock, version_argv: "--version", ver_pattern: "TeamViewer.*([0-9][0-9]+\\.[0-9]+\\.[0-9]+)" );
	if(teamViwVer[1]){
		set_kb_item( name: "TeamViewer/Linux/Ver", value: teamViwVer[1] );
		set_kb_item( name: "TeamViewer/Linux/detected", value: TRUE );
		cpe = build_cpe( value: teamViwVer[1], exp: "^([0-9.]+)", base: "cpe:/a:teamviewer:teamviewer:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:teamviewer:teamviewer";
		}
		register_and_report_cpe( app: "TeamViewer", ver: teamViwVer[1], base: "cpe:/a:teamviewer:teamviewer:", expr: "^([0-9.]+)", insloc: binary, concluded: teamViwVer[0] );
		exit( 0 );
	}
}
ssh_close_connection();
exit( 0 );

