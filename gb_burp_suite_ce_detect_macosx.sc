if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813610" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-06-19 16:38:09 +0530 (Tue, 19 Jun 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Burp Suite Community Edition Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Burp Suite Community Edition on MAC OS X.

  The script logs in via ssh, searches for folder
  'Burp Suite Community Edition Installer.app' and queries the related 'info.plist'
   file for string 'CFBundleShortVersionString' via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
burpVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Burp\\ Suite\\ Community\\ Edition\\ Installer.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( burpVer ) || ContainsString( burpVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "BurpSuite/CE/MacOSX/Version", value: burpVer );
cpe = build_cpe( value: burpVer, exp: "^([0-9.]+)", base: "cpe:/a:portswigger:burp_suite:" );
if(isnull( cpe )){
	cpe = "cpe:/a:portswigger:burp_suite";
}
register_product( cpe: cpe, location: "/Applications/Burp Suite Community Edition Installer.app" );
log_message( data: build_detection_report( app: "Burp Suite Community Edition", version: burpVer, install: "/Applications/Burp Suite Community Edition Installer.app", cpe: cpe, concluded: burpVer ) );
exit( 0 );

