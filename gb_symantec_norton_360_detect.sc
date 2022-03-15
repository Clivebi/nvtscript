if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808515" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-07-05 12:26:57 +0530 (Tue, 05 Jul 2016)" );
	script_name( "Symantec Norton 360 Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Symantec
  Norton 360.

  The script logs in via smb, searches for string 'Norton 360' in the registry
  and reads the version information from registry." );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(isnull( key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	nortonName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( nortonName, "Norton 360" )){
		nortonVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		nortonPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!nortonPath){
			nortonPath = "Couldn find the install location from registry";
		}
		if(nortonVer){
			set_kb_item( name: "Symantec/Norton/360/Ver", value: nortonVer );
			cpe = build_cpe( value: nortonVer, exp: "^([0-9.]+)", base: "cpe:/a:symantec:norton_360:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:symantec:norton_360";
			}
		}
		register_product( cpe: cpe, location: nortonPath );
		log_message( data: build_detection_report( app: "Norton 360", version: nortonVer, install: nortonPath, cpe: cpe, concluded: nortonVer ) );
		exit( 0 );
	}
}

