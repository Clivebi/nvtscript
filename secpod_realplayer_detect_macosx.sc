if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902622" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "RealNetworks RealPlayer Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of RealPlayer on MAC.

The script logs in via ssh, gets the version by using a command and set
it in the KB item." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
if(!get_kb_item( "ssh/login/osx_name" )){
	close( sock );
	exit( 0 );
}
realVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "RealPlayer.app/Contents/Info CFBundleShortVersionString" ) );
fullVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "RealPlayer.app/Contents/Info HelixVersion" ) );
close( sock );
if(isnull( realVer ) || ContainsString( realVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "RealPlayer/MacOSX/Version", value: realVer );
insloc = "Unable to find the install Location.";
if(fullVer){
	set_kb_item( name: "RealPlayer/MacOSX/FullVer", value: fullVer );
	register_and_report_cpe( app: "RealPlayer", ver: fullVer, concluded: fullVer, base: "cpe:/a:realnetworks:realplayer:", expr: "^([0-9.]+)", insloc: insloc );
	exit( 0 );
}
register_and_report_cpe( app: "RealPlayer", ver: realVer, concluded: realVer, base: "cpe:/a:realnetworks:realplayer:", expr: "^([0-9.]+)", insloc: insloc );

