if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902633" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-17 17:38:48 +0530 (Thu, 17 Nov 2011)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Fusion Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of VMware Fusion.

The script logs in via ssh, searches for folder 'VMware Fusion.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
vmfusionVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "VMware\\ Fusion.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( vmfusionVer ) || ContainsString( vmfusionVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "VMware/Fusion/MacOSX/Version", value: vmfusionVer );
cpe = build_cpe( value: vmfusionVer, exp: "^([0-9.]+)", base: "cpe:/a:vmware:fusion:" );
if(isnull( cpe )){
	cpe = "cpe:/a:vmware:fusion";
}
register_product( cpe: cpe, location: "/Applications/VMware Fusion.app" );
log_message( data: build_detection_report( app: "VMware Fusion", version: vmfusionVer, install: "/Applications/VMware Fusion.app", cpe: cpe, concluded: vmfusionVer ) );

