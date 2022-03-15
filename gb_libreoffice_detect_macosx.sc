if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803063" );
	script_version( "$Revision: 11284 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:30:56 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-11-26 17:26:43 +0530 (Mon, 26 Nov 2012)" );
	script_name( "LibreOffice Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of LibreOffice.

  The script logs in via ssh, searches for folder 'LibreOffice.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via command
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
if(!get_kb_item( "ssh/login/osx_name" )){
	close( sock );
	exit( 0 );
}
liboVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "LibreOffice.app/Contents/Info CFBundleGetInfoString" ) );
if(isnull( liboVer ) || ContainsString( liboVer, "does not exist" )){
	exit( 0 );
}
liboVer = eregmatch( pattern: "LibreOffice ([0-9.]+).*(Build:([0-9.]+))?", string: liboVer );
if(!liboVer){
	exit( 0 );
}
if(liboVer[1] && liboVer[3]){
	buildVer = liboVer[1] + "." + liboVer[3];
}
set_kb_item( name: "LibreOffice/MacOSX/Version", value: liboVer[1] );
set_kb_item( name: "LibreOffice/MacOSX/Installed", value: TRUE );
if(buildVer){
	set_kb_item( name: "LibreOffice-Build/MacOSX/Version", value: buildVer );
	set_kb_item( name: "LibreOffice/MacOSX/Installed", value: TRUE );
}
cpe = build_cpe( value: liboVer[1], exp: "^([0-9.]+)", base: "cpe:/a:libreoffice:libreoffice:" );
path = "/Applications/LibreOffice.app/";
if(isnull( cpe )){
	cpe = "cpe:/a:libreoffice:libreoffice";
}
register_product( cpe: cpe, location: path );
log_message( data: build_detection_report( app: "LibreOffice", version: liboVer[1], install: path, cpe: cpe, concluded: liboVer[1] ) );

