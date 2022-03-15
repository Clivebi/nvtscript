if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813553" );
	script_version( "$Revision: 13650 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2018-07-06 15:50:15 +0530 (Fri, 06 Jul 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "AnyDesk Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  AnyDesk.

  The script logs in via smb, searches for 'AnyDesk' in the registry and gets
  the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnyDesk" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnyDesk" )){
		exit( 0 );
	}
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnyDesk";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnyDesk";
	}
}
adVer = registry_get_sz( item: "DisplayVersion", key: key );
adPath = registry_get_sz( item: "InstallLocation", key: key );
if( !adPath ){
	adPath = "Unable to get install location from registry";
}
else {
	adPath = ereg_replace( pattern: "\"", string: adPath, replace: "" );
}
if( IsMatchRegexp( adVer, "ad [0-9.]+" ) ){
	version = ereg_replace( pattern: "ad ", string: adVer, replace: "" );
}
else {
	if(IsMatchRegexp( adVer, "[0-9.]+" )){
		version = adVer;
	}
}
if(version){
	set_kb_item( name: "AnyDesk/Win/Installed", value: TRUE );
	set_kb_item( name: "AnyDesk/Win/Ver", value: adVer );
	register_and_report_cpe( app: "AnyDesk", ver: version, base: "cpe:/a:anydesk:anydesk:", expr: "^([0-9.]+)", insloc: adPath );
}
exit( 0 );

