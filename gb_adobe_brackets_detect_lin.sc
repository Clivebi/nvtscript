if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808185" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-07-08 11:10:27 +0530 (Fri, 08 Jul 2016)" );
	script_name( "Adobe Brackets Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Brackets on Linux.

  The script logs in via ssh, searches for executable and queries the
  version from 'config.json' file." );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
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
bracbin = ssh_find_bin( prog_name: "brackets", sock: sock );
if(isnull( bracbin )){
	exit( 0 );
}
if(!paths = ssh_find_file( file_name: "/opt/brackets/www/config\\.json$", useregex: TRUE, sock: sock )){
	exit( 0 );
}
path = chomp( paths[0] );
if(!path){
	exit( 0 );
}
bracVer = ssh_get_bin_version( full_prog_name: "cat", version_argv: path, ver_pattern: "apiVersion\": \"([0-9.]+)\"", sock: sock );
if(bracVer[1] != NULL){
	set_kb_item( name: "Adobe/Brackets/Linux/Ver", value: bracVer[1] );
	cpe = build_cpe( value: bracVer[1], exp: "^([0-9.]+)", base: "cpe:/a:adobe:brackets:" );
	if(!cpe){
		cpe = "cpe:/a:adobe:brackets";
	}
	register_product( cpe: cpe, location: paths[0] );
	log_message( data: build_detection_report( app: "Adobe Brackets", version: bracVer[1], install: paths[0], cpe: cpe, concluded: bracVer[1] ) );
	exit( 0 );
}
ssh_close_connection();

