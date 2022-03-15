if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811126" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2017-05-29 16:58:07 +0530 (Mon, 29 May 2017)" );
	script_name( "IBM Tivoli Storage Manager Client Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  IBM Tivoli Storage Manager Client.

  The script logs in via smb, searches for 'IBM Tivoli Storage Manager Client'
  string in the registry, gets the install path from registry and fetches the
  version from executable file." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	tivName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( tivName, "IBM Tivoli Storage Manager Client" ) || ContainsString( tivName, "IBM Spectrum Protect Client" )){
		tivPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(tivPath){
			tivPath1 = tivPath + "baclient";
			tivVer = fetch_file_version( sysPath: tivPath1, file_name: "dsm.exe" );
			if(tivVer){
				set_kb_item( name: "IBM/Tivoli/Storage/Manager/Win/Ver", value: tivVer );
				cpe = build_cpe( value: tivVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:tivoli_storage_manager:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:ibm:tivoli_storage_manager";
				}
				if(ContainsString( os_arch, "64" )){
					set_kb_item( name: "IBM/Tivoli/Storage/Manager/Win64/Ver", value: tivVer );
					cpe = build_cpe( value: tivVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:tivoli_storage_manager:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:ibm:tivoli_storage_manager:x64";
					}
				}
				register_product( cpe: cpe, location: tivPath );
				log_message( data: build_detection_report( app: tivName, version: tivVer, install: tivPath, cpe: cpe, concluded: tivVer ) );
				exit( 0 );
			}
		}
	}
}

