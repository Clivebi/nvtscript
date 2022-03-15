if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102021" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-04-06 10:41:02 +0200 (Tue, 06 Apr 2010)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Apple Safari Detect Script (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of Apple Safari on Mac OS X.

The script logs in via ssh, searches for folder 'Safari.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
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
ver = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Safari.app/Contents/Info CFBundleShortVersionString" ) );
if(isnull( ver ) || ContainsString( ver, "does not exist" )){
	log_message( data: "exiting" + ver );
	exit( 0 );
}
set_kb_item( name: "AppleSafari/MacOSX/Version", value: ver );
cpe = build_cpe( value: ver, exp: "^([0-9.]+)", base: "cpe:/a:apple:safari:" );
if(isnull( cpe )){
	cpe = "cpe:/a:apple:safari";
}
register_product( cpe: cpe, location: "/Applications/Safari.app" );
log_message( data: build_detection_report( app: "Safari", version: ver, install: "/Applications/Safari.app", cpe: cpe, concluded: ver ) );

