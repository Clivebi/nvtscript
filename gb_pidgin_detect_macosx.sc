if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809872" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-01-20 15:36:08 +0530 (Fri, 20 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Pidgin Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Pidgin on MAC OS X.

  The script logs in via ssh, searches for folder 'pidgin' and queries the
  version from 'Changelog' file." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
pidgin_file = ssh_find_file( file_name: "/usr/local/Cellar/pidgin/ChangeLog$", useregex: TRUE, sock: sock );
for path in pidgin_file {
	path = chomp( path );
	if(!path){
		continue;
	}
	pidgin = ssh_get_bin_version( full_prog_name: "cat", version_argv: path, ver_pattern: "pidgin", sock: sock );
	if(pidgin[0] != NULL){
		pidgin_Ver = ssh_get_bin_version( full_prog_name: "cat", version_argv: path, ver_pattern: "version ([0-9.]+)", sock: sock );
		if(pidgin_Ver[1]){
			set_kb_item( name: "Pidgin/MacOSX/Version", value: pidgin_Ver[1] );
			cpe = build_cpe( value: pidgin_Ver[1], exp: "^([0-9.]+)", base: "cpe:/a:pidgin:pidgin:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:pidgin:pidgin";
			}
			register_product( cpe: cpe, location: path );
			log_message( data: build_detection_report( app: "Pidgin", version: pidgin_Ver[1], install: path, cpe: cpe, concluded: pidgin_Ver[1] ) );
			exit( 0 );
		}
	}
}
close( sock );
exit( 0 );

