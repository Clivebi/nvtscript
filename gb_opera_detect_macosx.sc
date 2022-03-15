if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802142" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Opera Browser Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of Opera on Mac OS X.

The script logs in via ssh, searches for folder 'Opera.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
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
operaVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Opera.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( operaVer ) || ContainsString( operaVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "Opera/MacOSX/Version", value: operaVer );
cpe = build_cpe( value: operaVer, exp: "^([0-9.]+)", base: "cpe:/a:opera:opera_browser:" );
if(isnull( cpe )){
	cpe = "cpe:/a:opera:opera_browser";
}
register_product( cpe: cpe, location: "/Applications/Opera.app" );
log_message( data: build_detection_report( app: "Opera", version: operaVer, install: "/Applications/Opera.app", cpe: cpe, concluded: operaVer ) );

