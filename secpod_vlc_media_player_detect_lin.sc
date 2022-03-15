if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900529" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VLC Media Player Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of
  VLC Media Player version on Linux.

  This script logs in via shh, extracts the version from the binary file." );
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
vlcBinPath = ssh_find_bin( prog_name: "vlc", sock: sock );
for binPath in vlcBinPath {
	path = chomp( binPath );
	if(!path){
		continue;
	}
	vlcVer = ssh_get_bin_version( full_prog_name: path, version_argv: "--version", ver_pattern: "VLC version ([0-9\\.]+[a-z]?)", sock: sock );
	if(vlcVer[1] != NULL){
		set_kb_item( name: "VLCPlayer/Lin/Ver", value: vlcVer[1] );
		ssh_close_connection();
		cpe = build_cpe( value: vlcVer[1], exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:videolan:vlc_media_player:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:videolan:vlc_media_player";
		}
		register_product( cpe: cpe, location: path );
		log_message( data: build_detection_report( app: "VLC Media Player", version: vlcVer[1], install: path, cpe: cpe, concluded: vlcVer[1] ) );
		exit( 0 );
	}
}
ssh_close_connection();

