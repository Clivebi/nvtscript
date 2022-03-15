if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809016" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-08-29 13:05:30 +0530 (Mon, 29 Aug 2016)" );
	script_name( "Flexera InstallAnywhere Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Flexera InstallAnywhere on Linux.

  The script logs in via ssh, searches for executable and queries the
  version from 'config.json' file." );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
paths = ssh_find_file( file_name: "/InstallAnywhere\\.lax$", useregex: TRUE, sock: sock );
for path in paths {
	path = chomp( path );
	if(!path){
		continue;
	}
	path_new = ereg_replace( pattern: " ", string: path, replace: "\\ " );
	installVer = ssh_get_bin_version( full_prog_name: "cat", version_argv: path_new, ver_pattern: "lax.version=([0-9.]+)", sock: sock );
	if(installVer[1] != NULL){
		set_kb_item( name: "InstallAnywhere/Linux/Ver", value: installVer[1] );
		cpe = build_cpe( value: installVer[1], exp: "^([0-9.]+)", base: "cpe:/a:flexerasoftware:installanywhere:" );
		if(!cpe){
			cpe = "cpe:/a:flexerasoftware:installanywhere";
		}
		register_product( cpe: cpe, location: path );
		log_message( data: build_detection_report( app: "Flexera InstallAnywhere", version: installVer[1], install: path, cpe: cpe, concluded: installVer[1] ) );
		exit( 0 );
	}
}
close( sock );

