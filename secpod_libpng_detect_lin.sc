if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900070" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "libpng Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of libpng.

  The script logs in via ssh, searches for executable 'libpng-config' and
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
pngName = ssh_find_file( file_name: "/libpng-config$", useregex: TRUE, sock: sock );
if(!pngName){
	ssh_close_connection();
	exit( 0 );
}
for executableFile in pngName {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	pngVer = ssh_get_bin_version( full_prog_name: executableFile, version_argv: "--version", ver_pattern: "[0-9.]{3,}", sock: sock );
	if(!isnull( pngVer[0] )){
		set_kb_item( name: "Libpng/Version", value: pngVer[0] );
		cpe = build_cpe( value: pngVer[0], exp: "^([0-9.]+)", base: "cpe:/a:libpng:libpng:" );
		if(!isnull( cpe )){
			register_product( cpe: cpe, location: executableFile );
		}
		log_message( data: "Detected libpng version: " + pngVer[0] + "\nLocation: " + executableFile + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + pngVer[max_index( pngVer ) - 1] );
	}
}
ssh_close_connection();

