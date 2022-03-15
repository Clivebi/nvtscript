if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800253" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Evolution Data Server Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Evolution.

The script logs in via ssh, searches for executable 'evolution' and
queries the found executables via command line option '--version'." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
evolution = ssh_find_file( file_name: "/evolution$", useregex: TRUE, sock: sock );
for executableFile in evolution {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	evolutionVer = ssh_get_bin_version( full_prog_name: executableFile, version_argv: "--version", ver_pattern: "evolution ([0-9.]+)", sock: sock );
	if(evolutionVer[1] != NULL){
		set_kb_item( name: "Evolution/Ver", value: evolutionVer[1] );
		cpe = build_cpe( value: evolutionVer[1], exp: "^([0-9.]+)", base: "cpe:/a:gnome:evolution:" );
		if(!isnull( cpe )){
			register_product( cpe: cpe, location: executableFile );
		}
		log_message( data: "Detected Evolution Data Server version: " + evolutionVer[1] + "\nLocation: " + executableFile + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + evolutionVer[max_index( evolutionVer ) - 1] );
	}
}
ssh_close_connection();

