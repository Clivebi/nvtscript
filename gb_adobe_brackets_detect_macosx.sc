if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808178" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-07-08 11:10:27 +0530 (Fri, 08 Jul 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Brackets Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Brackets on MAC OS X.

  The script logs in via ssh, searches for folder 'Brackets.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via command
  line option 'defaults read'." );
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
bracVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Brackets.app/Contents/Info " + "CFBundleShortVersionString" ) );
close( sock );
if(isnull( bracVer ) || ContainsString( bracVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "AdobeBrackets/MacOSX/Version", value: bracVer );
cpe = build_cpe( value: bracVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:brackets:" );
if(isnull( cpe )){
	cpe = "cpe:/a:adobe:brackets";
}
register_product( cpe: cpe, location: "/Applications/Brackets.app" );
log_message( data: build_detection_report( app: "Adobe Brackets", version: bracVer, install: "/Applications/Brackets.app/", cpe: cpe, concluded: bracVer ) );
exit( 0 );

