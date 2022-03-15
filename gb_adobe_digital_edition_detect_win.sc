if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804300" );
	script_version( "$Revision: 14329 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-03 13:43:16 +0530 (Mon, 03 Feb 2014)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Digital Edition Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe Digital Edition on Windows.

The script logs in via smb, searches for Adobe Digital in the registry
and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Adobe" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Adobe" )){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		digName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( digName, "Adobe Digital Editions" )){
			digVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			digPath = registry_get_sz( key: key + item, item: "UninstallString" );
			if( !digPath ){
				digPath = "Couldn find the install location from registry";
			}
			else {
				digPath = digPath - "uninstall.exe";
			}
			if(digVer){
				set_kb_item( name: "AdobeDigitalEdition/Win/Ver", value: digVer );
				cpe = build_cpe( value: digVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:digital_editions:" );
				if(!cpe){
					cpe = "cpe:/a:adobe:digital_editions";
				}
				if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "AdobeDigitalEdition64/Win/Ver", value: digVer );
					cpe = build_cpe( value: digVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:digital_editions:x64:" );
					if(!cpe){
						cpe = "cpe:/a:adobe:digital_editions:x64";
					}
				}
				register_product( cpe: cpe, location: digPath );
				log_message( data: build_detection_report( app: "Adobe Digital Edition", version: digVer, install: digPath, cpe: cpe, concluded: digVer ) );
			}
		}
	}
}

