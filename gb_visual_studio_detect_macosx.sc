if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814699" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-03-14 12:34:57 +0530 (Thu, 14 Mar 2019)" );
	script_name( "Visual Studio Version Detection (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	script_xref( name: "URL", value: "https://visualstudio.microsoft.com" );
	script_tag( name: "summary", value: "Detects the installed version of
  Visual Studio on MAC OS X.

  The script logs in via ssh, searches for folder 'Visual Studio.app' and queries the
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
vsVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Visual\\ Studio.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( vsVer ) || ContainsString( vsVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "VisualStudio/MacOSX/Version", value: vsVer );
cpe = build_cpe( value: vsVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:visual_studio:" );
if(isnull( cpe )){
	cpe = "cpe:/a:microsoft:visual_studio";
}
location = "/Applications/Visual\\ " + "Studio.app";
register_product( cpe: cpe, location: location );
log_message( data: build_detection_report( app: "Microsoft Visual Studio", version: vsVer, install: "/Applications/Visual Studio.app", cpe: cpe, concluded: vsVer ) );
exit( 0 );

