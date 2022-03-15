if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802959" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-09-11 16:00:34 +0530 (Tue, 11 Sep 2012)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe LiveCycle Designer Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe LiveCycle Designer.

The script logs in via smb, searches for Adobe LiveCycle Designer in the registry
and gets the version from registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Adobe\\Designer" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Adobe\\Designer" )){
		exit( 0 );
	}
}
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
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	designName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( designName, "Adobe LiveCycle Designer" )){
		esName = eregmatch( pattern: "ES([0-9.]+)", string: designName );
		designPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(designPath){
			designVer = fetch_file_version( sysPath: designPath, file_name: "FormDesigner.exe" );
			if(designVer){
				set_kb_item( name: "Adobe/LiveCycle/Designer", value: designVer );
				if( esName[0] ){
					esName[0] = tolower( esName[0] );
					cpe = build_cpe( value: designVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:livecycle_designer_" + esName[0] + ":" );
				}
				else {
					cpe = build_cpe( value: designVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:livecycle_designer:" );
				}
				if(isnull( cpe )){
					cpe = "cpe:/a:adobe:livecycle_designer";
				}
				register_product( cpe: cpe, location: designPath );
				log_message( data: build_detection_report( app: "Adobe LiveCycle Designer", version: designVer, install: designPath, cpe: cpe, concluded: designVer ) );
			}
		}
	}
}

