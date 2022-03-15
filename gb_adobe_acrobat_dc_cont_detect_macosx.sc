if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812930" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-02-15 15:00:46 +0530 (Thu, 15 Feb 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Acrobat DC (Continuous Track) Detect (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Acrobat DC (Continuous Track).

  The script logs in via ssh, searches for folder 'Adobe Acrobat DC'
  and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	script_xref( name: "URL", value: "https://acrobat.adobe.com/us/en/acrobat.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
psVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Adobe\\ Acrobat\\ DC/Adobe\\ Acrobat.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( psVer ) || ContainsString( psVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "Adobe/AcrobatDC/Continuous/MacOSX/Version", value: psVer );
cpe = build_cpe( value: psVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:acrobat_dc_continuous:" );
if(isnull( cpe )){
	cpe = "cpe:/a:adobe:acrobat_dc_continuous";
}
register_product( cpe: cpe, location: "/Applications/Adobe Acrobat DC" );
log_message( data: build_detection_report( app: "Adobe Acrobat DC Continuous Track", version: psVer, install: "/Applications/Adobe Acrobat DC", cpe: cpe, concluded: psVer ) );
exit( 0 );

