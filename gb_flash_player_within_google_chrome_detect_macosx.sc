if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810614" );
	script_version( "2021-02-08T13:19:59+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-08 13:19:59 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-03-14 15:08:22 +0530 (Tue, 14 Mar 2017)" );
	script_name( "Adobe Flash Player Within Google Chrome Detection (Mac OS X SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/flash-player/kb/flash-player-google-chrome.html" );
	script_tag( name: "summary", value: "SSH login-based detection of Adobe Flash Player within Google Chrome." );
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
flashIns = ssh_cmd( socket: sock, cmd: "ls ~/Library/Application\\ Support/Google/Chrome/PepperFlash" );
versions = str_replace( find: "\n", replace: " ", string: flashIns );
versionList = split( buffer: versions, sep: " ", keep: FALSE );
maxVer = versionList[1];
for version in versionList {
	if( IsMatchRegexp( version, "^[0-9]+" ) && maxVer < version ){
		maxVer = version;
	}
	else {
		continue;
	}
}
flashVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read ~/Library/Application\\ Support/Google/Chrome/PepperFlash/" + maxVer + "/PepperFlashPlayer.plugin/Contents/Info.plist CFBundleVersion" ) );
if(!flashVer || ContainsString( flashVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "adobe/flash_player/detected", value: TRUE );
set_kb_item( name: "AdobeFlashPlayer/Chrome/MacOSX/Ver", value: flashVer );
cpe = build_cpe( value: flashVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:flash_player_chrome:" );
if(!cpe){
	cpe = "cpe:/a:adobe:flash_player_chrome";
}
register_product( cpe: cpe, location: "/Applications/", port: 0, service: "ssh-login" );
log_message( data: build_detection_report( app: "Adobe Flash Player within Google Chrome", version: flashVer, install: "/Applications/", cpe: cpe, concluded: flashVer ) );
exit( 0 );

