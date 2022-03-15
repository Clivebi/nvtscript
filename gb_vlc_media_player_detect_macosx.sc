if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802724" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-03-22 15:56:23 +0530 (Thu, 22 Mar 2012)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VLC Media Player Version Detection (MacOSX)" );
	script_tag( name: "summary", value: "Detects the installed version of VLC
  Media Player.

  This script logs in via ssh, searches for folder 'VLC.app' and queries the
  related 'info.plist' file for string 'CFBundleShortVersionString' via command
  line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_family( "Product detection" );
	script_mandatory_keys( "ssh/login/osx_name" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
vlcVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "VLC.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(!vlcVer || ContainsString( vlcVer, "does not exist" )){
	exit( 0 );
}
cpe = build_cpe( value: vlcVer, exp: "^([0-9.]+)", base: "cpe:/a:videolan:vlc_media_player:" );
if(isnull( cpe )){
	cpe = "cpe:/a:videolan:vlc_media_player";
}
register_product( cpe: cpe, location: "/Applications/VLC.app" );
set_kb_item( name: "VLC/Media/Player/MacOSX/Version", value: vlcVer );
log_message( data: build_detection_report( app: "VLC Media Player", version: vlcVer, install: "/Applications/VLC.app", cpe: cpe, concluded: vlcVer ) );

