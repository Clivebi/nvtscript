if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801301" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Skype Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script finds the installed version of Skype.

The script logs in via smb, searches for Skype in the registry
and gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
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
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Skype" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Skype" )){
		exit( 0 );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		skName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( skName, "Skype" )){
			skVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(skVer){
				skPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!skPath){
					skPath = "Couldn find the install location from registry";
				}
				set_kb_item( name: "Skype/Win/Ver", value: skVer );
				cpe = build_cpe( value: skVer, exp: "^([0-9.]+)", base: "cpe:/a:skype:skype:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:skype:skype";
				}
				register_product( cpe: cpe, location: skPath );
				log_message( data: build_detection_report( app: "Skype", version: skVer, install: skPath, cpe: cpe, concluded: skVer ) );
			}
		}
	}
}

