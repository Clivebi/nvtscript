if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900563" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "ImageMagick version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of
  ImageMagick on Linux.

  The script logs in via ssh, searches for executable 'identify' and
  queries the found executables via command line option '-version'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
getPath = ssh_find_bin( prog_name: "identify", sock: sock );
for executableFile in getPath {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	imageVer = ssh_get_bin_version( full_prog_name: executableFile, version_argv: "-version", ver_pattern: "ImageMagick ([0-9.]+\\-?[0-9]{0,3})", sock: sock );
	if(imageVer[1] != NULL){
		imageVer[1] = ereg_replace( pattern: "-", string: imageVer[1], replace: "." );
		set_kb_item( name: "ImageMagick/Lin/Ver", value: imageVer[1] );
		ssh_close_connection();
		register_and_report_cpe( app: "ImageMagick", ver: imageVer[1], concluded: imageVer[0], base: "cpe:/a:imagemagick:imagemagick:", expr: "^([0-9.]+)", insloc: executableFile );
		exit( 0 );
	}
}
ssh_close_connection();

