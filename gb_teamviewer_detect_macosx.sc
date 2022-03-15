if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813896" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-09-07 13:42:31 +0530 (Fri, 07 Sep 2018)" );
	script_name( "TeamViewer Version Detection (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	script_xref( name: "URL", value: "https://www.teamviewer.com/en" );
	script_tag( name: "summary", value: "Detects the installed version of
  TeamViewer on MAC OS X.

  The script logs in via ssh, searches for folder 'TeamViewer.app' and queries the
  related 'info.plist' file for string 'CFBundleShortVersionString' via command line
  option 'defaults read'." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
teamVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "TeamViewer.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( teamVer ) || ContainsString( teamVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "TeamViewer/MacOSX/Version", value: teamVer );
cpe = build_cpe( value: teamVer, exp: "^([0-9.]+)", base: "cpe:/a:teamviewer:teamviewer:" );
if(isnull( cpe )){
	cpe = "cpe:/a:teamviewer:teamviewer";
}
register_product( cpe: cpe, location: "/Applications/TeamViewer.app" );
log_message( data: build_detection_report( app: "TeamViewer", version: teamVer, install: "/Applications/TeamViewer.app", cpe: cpe, concluded: teamVer ) );
exit( 0 );

