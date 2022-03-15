if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810259" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-12-21 19:01:05 +0530 (Wed, 21 Dec 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "ImageMagick Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  ImageMagick on MAC OS X.

  The script logs in via ssh, searches for executable and queries the
  version from 'Magick-config' file." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
magickFile = ssh_find_file( file_name: "/Magick-config$", useregex: TRUE, sock: sock );
for path in magickFile {
	path = chomp( path );
	if(!path){
		continue;
	}
	magickVer = ssh_get_bin_version( full_prog_name: path, version_argv: "--version", ver_pattern: "([0-9.]+\\-?[0-9]{0,3})", sock: sock );
	if(magickVer[0] != NULL){
		magickVer[0] = ereg_replace( pattern: "-", string: magickVer[0], replace: "." );
		set_kb_item( name: "ImageMagick/MacOSX/Version", value: magickVer[0] );
		register_and_report_cpe( app: "ImageMagick", ver: magickVer[0], concluded: magickVer[0], base: "cpe:/a:imagemagick:imagemagick:", expr: "^([0-9.]+)", insloc: magickFile[0] );
		close( sock );
		exit( 0 );
	}
}
close( sock );
exit( 0 );

