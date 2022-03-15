if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810240" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-12-15 12:59:49 +0530 (Thu, 15 Dec 2016)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "Adobe InDesign Server Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe InDesign Server on MAC OS X.

  The script logs in via ssh, searches for folder 'install.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
name = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "install.app/Contents/Info " + "CFBundleGetInfoString" ) );
if( IsMatchRegexp( name, "Copyright.*Adobe Systems" ) ){
	installVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "install.app/Contents/Info " + "CFBundleVersion" ) );
}
else {
	installVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Adobe\\ InDesign\\ CC\\ 2018/Adobe\\ InDesign\\ CC\\ 2018.app/Contents/Info " + "CFBundleShortVersionString" ) );
}
close( sock );
if(isnull( installVer ) || ContainsString( installVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "InDesign/Server/MacOSX/Version", value: installVer );
cpe = build_cpe( value: installVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:indesign_server:" );
if(isnull( cpe )){
	cpe = "cpe:/a:adobe:indesign_server";
}
register_product( cpe: cpe, location: "/Applications" );
log_message( data: build_detection_report( app: "Adobe Indesign Server", version: installVer, install: "/Applications", cpe: cpe, concluded: installVer ) );
exit( 0 );

