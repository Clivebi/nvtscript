if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810265" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2017-01-10 12:53:05 +0530 (Tue, 10 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Tools Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of
  VMware Tools on MAC OS X.

  The script logs in via ssh, searches for folder 'Uninstall VMware Tools.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
vmtoolVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Library/" + "Application\\ Support/VMware\\ Tools/Uninstall\\ VMware\\ Tools.app/Contents/Info " + "CFBundleShortVersionString" ) );
close( sock );
if(isnull( vmtoolVer ) || ContainsString( vmtoolVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "VMwareTools/MacOSX/Version", value: vmtoolVer );
cpe = build_cpe( value: vmtoolVer, exp: "^([0-9.]+)", base: "cpe:/a:vmware:tools:" );
if(isnull( cpe )){
	cpe = "cpe:/a:vmware:tools";
}
register_product( cpe: cpe, location: "/Library" );
log_message( data: build_detection_report( app: "VMware Tools", version: vmtoolVer, install: "/Library", cpe: cpe, concluded: vmtoolVer ) );
exit( 0 );

