if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809737" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-12-01 17:27:04 +0530 (Thu, 01 Dec 2016)" );
	script_name( "FreeRDP Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of
  FreeRDP.

  The script logs in via ssh, searches for executable 'xfreerdp' and
  queries the found executables via command line option '--version'." );
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
binFiles = ssh_find_file( file_name: "/xfreerdp$", useregex: TRUE, sock: sock );
if(!binFiles){
	ssh_close_connection();
	exit( 0 );
}
for executableFile in binFiles {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	ftVer = ssh_get_bin_version( full_prog_name: executableFile, sock: sock, version_argv: "--version", ver_pattern: "([0-9.]{3,}(-[A-Za-z0-9+]+)?)" );
	if(!isnull( ftVer[1] )){
		set_kb_item( name: "FreeRDP/Linux/Ver", value: ftVer[1] );
		cpe = build_cpe( value: ftVer[1], exp: "^([0-9.]+-?[A-Za-z0-9]+?[+]?[0-9]+?)", base: "cpe:/a:freerdp_project:freerdp:" );
		if(!cpe){
			cpe = "cpe:/a:freerdp_project:freerdp";
		}
		register_product( cpe: cpe, location: executableFile );
		log_message( data: build_detection_report( app: "FreeRDP", version: ftVer[1], install: executableFile, cpe: cpe, concluded: ftVer[1] ) );
		exit( 0 );
		close( sock );
	}
}
close( sock );

