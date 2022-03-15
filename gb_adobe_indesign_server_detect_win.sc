if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810239" );
	script_version( "$Revision: 14329 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-15 12:59:49 +0530 (Thu, 15 Dec 2016)" );
	script_name( "Adobe InDesign Server Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe InDesign Server.

  The script logs in via smb, searches for Adobe InDesign Server in the
  registry and gets the version from 'DisplayVersion' string from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
		if(IsMatchRegexp( digName, "Adobe Indesign.*Server" )){
			digVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			digPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!digPath){
				digPath = "Couldn find the install location from registry";
			}
			if(digVer){
				set_kb_item( name: "AdobeIndesignServer/Win/Ver", value: digVer );
				cpe = build_cpe( value: digVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:indesign_server:" );
				if(!cpe){
					cpe = "cpe:/a:adobe:indesign_server";
				}
				if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "AdobeIndesignServer64/Win/Ver", value: digVer );
					cpe = build_cpe( value: digVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:indesign_server:x64:" );
					if(!cpe){
						cpe = "cpe:/a:adobe:indesign_server:x64";
					}
				}
				register_product( cpe: cpe, location: digPath );
				log_message( data: build_detection_report( app: "Adobe Indesign Server", version: digVer, install: digPath, cpe: cpe, concluded: digVer ) );
			}
		}
	}
}

