if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811778" );
	script_version( "$Revision: 10896 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2017-09-19 12:52:53 +0530 (Tue, 19 Sep 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "CCleaner Cloud Agent Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  CCleaner Cloud Agent.

  The script logs in via smb, searches for 'CCleaner Cloud Installer' string and
  gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CCleaner Cloud\\" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CCleaner Cloud\\" )){
		exit( 0 );
	}
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CCleaner Cloud\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CCleaner Cloud\\";
	}
}
appName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( appName, "CCleaner Cloud" )){
	appVer = registry_get_sz( key: key, item: "DisplayVersion" );
	if(appVer){
		insloc = registry_get_sz( key: key, item: "InstallLocation" );
		if(!insloc){
			insloc = "Unknown";
		}
		set_kb_item( name: "CCleaner/Cloud/Win/Ver", value: appVer );
		cpe = build_cpe( value: appVer, exp: "([0-9.]+)", base: "cpe:/a:piriform:ccleaner_cloud:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:piriform:ccleaner_cloud";
		}
		register_product( cpe: cpe, location: insloc );
		log_message( data: build_detection_report( app: "CCleaner Cloud Agent (Installer)", version: appVer, install: insloc, cpe: cpe, concluded: appVer ) );
		exit( 0 );
	}
}
exit( 0 );

