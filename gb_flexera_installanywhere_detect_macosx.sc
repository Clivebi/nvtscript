if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809015" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-08-29 13:05:30 +0530 (Mon, 29 Aug 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Flexera InstallAnywhere Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Flexera InstallAnywhere on MAC OS X.

  The script logs in via ssh, searches for folder 'install.app' and
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
name = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "install.app/Contents/Info " + "CFBundleGetInfoString" ) );
if(IsMatchRegexp( name, "InstallAnywhere ([0-9]+)?" ) && ContainsString( name, "Flexera Software" )){
	installVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "install.app/Contents/Info " + "CFBundleVersion" ) );
	close( sock );
	if(isnull( installVer ) || ContainsString( installVer, "does not exist" )){
		exit( 0 );
	}
	set_kb_item( name: "InstallAnywhere/MacOSX/Version", value: installVer );
	cpe = build_cpe( value: installVer, exp: "^([0-9.]+)", base: "cpe:/a:flexerasoftware:installanywhere:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:flexerasoftware:installanywhere";
	}
	register_product( cpe: cpe, location: "/Applications" );
	log_message( data: build_detection_report( app: "Flexera InstallAnywhere", version: installVer, install: "/Applications", cpe: cpe, concluded: installVer ) );
	exit( 0 );
}

