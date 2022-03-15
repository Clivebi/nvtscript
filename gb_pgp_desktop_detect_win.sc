if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800215" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Symantec PGP/Encryption Desktop Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Symantec PGP/Encryption Desktop on Windows.

The script logs in via smb, search for the product name in the registry, gets
version from the 'DisplayVersion' string and set it in the KB item." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: "SOFTWARE\\PGP Corporation\\PGP" )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( appName, "PGP Desktop" ) || ContainsString( appName, "Symantec Encryption Desktop" )){
		insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!insloc){
			insloc = "Could not find the install location from registry";
		}
		deskVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!deskVer){
			exit( 0 );
		}
		if( ContainsString( appName, "PGP Desktop" ) ){
			set_kb_item( name: "PGPDesktop_or_EncryptionDesktop/Win/Installed", value: TRUE );
			if( ContainsString( os_arch, "x64" ) ){
				set_kb_item( name: "PGPDesktop64/Win/Ver", value: deskVer );
				register_and_report_cpe( app: appName, ver: deskVer, base: "cpe:/a:symantec:pgp_desktop:x64:", expr: "^([0-9.]+)", insloc: insloc );
			}
			else {
				set_kb_item( name: "PGPDesktop/Win/Ver", value: deskVer );
				register_and_report_cpe( app: appName, ver: deskVer, base: "cpe:/a:symantec:pgp_desktop:", expr: "^([0-9.]+)", insloc: insloc );
			}
		}
		else {
			set_kb_item( name: "PGPDesktop_or_EncryptionDesktop/Win/Installed", value: TRUE );
			if( ContainsString( os_arch, "x64" ) ){
				set_kb_item( name: "EncryptionDesktop64/Win/Ver", value: deskVer );
				register_and_report_cpe( app: appName, ver: deskVer, base: "cpe:/a:symantec:encryption_desktop:x64:", expr: "^([0-9.]+)", insloc: insloc );
			}
			else {
				set_kb_item( name: "EncryptionDesktop/Win/Ver", value: deskVer );
				register_and_report_cpe( app: appName, ver: deskVer, base: "cpe:/a:symantec:encryption_desktop:", expr: "^([0-9.]+)", insloc: insloc );
			}
		}
	}
}

