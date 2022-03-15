if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900661" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Pidgin Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Pidgin.

The script logs in via ssh, searches for executable 'pidgin' and
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
paths = ssh_find_file( file_name: "/pidgin$", useregex: TRUE, sock: sock );
for executableFile in paths {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	pidginVer = ssh_get_bin_version( full_prog_name: executableFile, sock: sock, version_argv: "--version", ver_pattern: "Pidgin ([0-9.]+)" );
	if(pidginVer[1] != NULL){
		set_kb_item( name: "Pidgin/Lin/Ver", value: pidginVer[1] );
		cpe = build_cpe( value: pidginVer[1], exp: "^([0-9.]+)", base: "cpe:/a:pidgin:pidgin:" );
		if(!cpe){
			cpe = "cpe:/a:pidgin:pidgin";
		}
		register_product( cpe: cpe, location: executableFile );
		log_message( data: "Detected Pidgin version: " + pidginVer[1] + "\nLocation: " + executableFile + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + pidginVer[max_index( pidginVer ) - 1] );
	}
}
ssh_close_connection();

