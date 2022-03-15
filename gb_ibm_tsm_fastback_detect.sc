if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805598" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-07-02 15:00:07 +0530 (Thu, 02 Jul 2015)" );
	script_name( "IBM Tivoli Storage Manager FastBack Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  IBM Tivoli Storage Manager FastBack.

  The script logs in via smb, searches for 'IBM Tivoli Storage Manager FastBack'
  string in the registry and gets the version from registry." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(ContainsString( tivName, "IBM Tivoli Storage Manager FastBack" )){
		tivPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(tivPath){
			tivPath1 = tivPath + "mount\\FastBackMount.exe";
			tivVer = GetVersionFromFile( file: tivPath1, verstr: "prod" );
			if(!tivVer){
				tivPath1 = tivPath + "common\\contain.exe";
				tivVer = GetVersionFromFile( file: tivPath1, verstr: "prod" );
			}
		}
		if(tivVer){
			set_kb_item( name: "IBM/Tivoli/Storage/Manager/FastBack/Win/Ver", value: tivVer );
			cpe = build_cpe( value: tivVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:tivoli_storage_manager_fastback:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:ibm:tivoli_storage_manager_fastback";
			}
			if(ContainsString( os_arch, "64" )){
				set_kb_item( name: "IBM/Tivoli/Storage/Manager/FastBack/Win64/Ver", value: tivVer );
				cpe = build_cpe( value: tivVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:tivoli_storage_manager_fastback:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:ibm:tivoli_storage_manager_fastback:x64";
				}
			}
			register_product( cpe: cpe, location: tivPath );
			log_message( data: build_detection_report( app: tivName, version: tivVer, install: tivPath, cpe: cpe, concluded: tivVer ) );
			exit( 0 );
		}
	}
}

