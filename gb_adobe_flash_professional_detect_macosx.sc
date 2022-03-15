if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802784" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-16 11:25:30 +0530 (Wed, 16 May 2012)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Flash Professional Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe Flash Professional.

The script logs in via ssh, searches for folder 'Adobe Flash CS.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'." );
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
for ver in make_list( "3",
	 "4",
	 "5",
	 "5.5",
	 "5.5.1",
	 "6" ) {
	flashVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Adobe\\ Flash\\ CS" + ver + "/Adobe\\ Flash\\ CS" + ver + ".app/Contents/Info CFBundleShortVersionString" ) );
	if(isnull( flashVer ) || ContainsString( flashVer, "does not exist" )){
		continue;
	}
	set_kb_item( name: "Adobe/Flash/Prof/MacOSX/Version", value: flashVer );
	cpe = build_cpe( value: flashVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:flash_cs" + ver + ":" );
	if(isnull( cpe )){
		cpe = "cpe:/a:adobe:flash_cs" + ver;
	}
	path = "/Applications/Adobe Flash CS" + ver;
	register_product( cpe: cpe, location: path );
	log_message( data: build_detection_report( app: "Adobe Flash Professional", version: flashVer, install: path, cpe: cpe, concluded: flashVer ) );
}
close( sock );

