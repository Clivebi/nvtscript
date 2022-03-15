if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802762" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-04-24 14:25:07 +0530 (Tue, 24 Apr 2012)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Wireshark Version Detection (MacOSX)" );
	script_tag( name: "summary", value: "Detects the installed version of Wireshark on Mac OS X.

The script logs in via ssh, searches for folder 'Wireshark.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
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
if(!get_kb_item( "ssh/login/osx_name" )){
	close( sock );
	exit( 0 );
}
sharkVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Wireshark.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( sharkVer ) || ContainsString( sharkVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "Wireshark/MacOSX/Version", value: sharkVer );
cpe = build_cpe( value: sharkVer, exp: "^([0-9.]+)", base: "cpe:/a:wireshark:wireshark:" );
if(isnull( cpe )){
	cpe = "cpe:/a:wireshark:wireshark";
}
register_product( cpe: cpe, location: "/Applications/Wireshark.app" );
log_message( data: build_detection_report( app: "Wireshark", version: sharkVer, install: "/Applications/Wireshark.app", cpe: cpe, concluded: sharkVer ) );

