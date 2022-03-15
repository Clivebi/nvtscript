if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808533" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-07-05 11:35:48 +0530 (Tue, 05 Jul 2016)" );
	script_name( "Symantec Antivirus Engine Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Symantec
  Antivirus Engine.
  The script logs in via smb, searches for string 'Symantec Antivirus Engine' in
  the registry and reads the version information from registry." );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
key = "SOFTWARE\\Symantec\\SharedDefs\\";
if(isnull( key )){
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
	symName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( symName, "Symantec Endpoint Protection Manager" )){
		symPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!symPath){
			symPath = "Couldn find the install location from registry";
		}
		key_list = make_list( "SOFTWARE\\Symantec\\SharedDefs\\SymcData-spcVirDef32Reduced\\",
			 "SOFTWARE\\Symantec\\SharedDefs\\SymcData-spcVirDef32\\",
			 "SOFTWARE\\Symantec\\SharedDefs\\SymcData-spcVirDef64Reduced\\",
			 "SOFTWARE\\Symantec\\SharedDefs\\SymcData-spcVirDef64\\" );
		for key1 in key_list {
			appPath = registry_get_sz( key: key1, item: "SesmInstallApp" );
			if(appPath){
				break;
			}
		}
		symVer = fetch_file_version( sysPath: appPath, file_name: "naveng32.dll" );
		if(symVer){
			set_kb_item( name: "Symantec/Antivirus/Engine/Ver", value: symVer );
			register_and_report_cpe( app: "Symantec Antivirus Engine", ver: symVer, concluded: symVer, base: "cpe:/a:symantec:anti-virus_engine:", expr: "^([0-9.]+)", insloc: symPath );
		}
		exit( 0 );
	}
}

