if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900966" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-15 12:44:36 +0530 (Tue, 15 Nov 2011)" );
	script_name( "CA Technologies Multiple Products Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of multiple CA Technologies products." );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\ComputerAssociates" )){
	exit( 0 );
}
key = "SOFTWARE\\ComputerAssociates\\ProductInfoWSC";
ezavName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( ezavName, "eTrust EZ Antivirus" )){
	ezavVer = registry_get_sz( key: key, item: "ProductVersion" );
	if(ezavVer){
		set_kb_item( name: "CA/Multiple_Products/Win/Installed", value: TRUE );
		set_kb_item( name: "CA/eTrust-EZ-AV/Win/Ver", value: ezavVer );
		register_and_report_cpe( app: ezavName, ver: ezavVer, base: "cpe:/a:ca:etrust_ez_antivirus:", expr: "^([0-9.]+)" );
	}
}
key = "SOFTWARE\\ComputerAssociates\\eTrust Suite Personal\\";
caavName = registry_get_sz( key: key + "\\av", item: "Name" );
if(ContainsString( caavName, "Anti-Virus" )){
	caavVer = registry_get_sz( key: key + "\\av", item: "Version" );
	if(caavVer){
		set_kb_item( name: "CA/Multiple_Products/Win/Installed", value: TRUE );
		set_kb_item( name: "CA/AV/Win/Ver", value: caavVer );
		register_and_report_cpe( app: caavName, ver: caavVer, base: "cpe:/a:ca:anti-virus:", expr: "^([0-9.]+)" );
	}
}
caissName = registry_get_sz( key: key + "\\suite", item: "Name" );
if(ContainsString( caissName, "Internet Security Suite" )){
	caissVer = registry_get_sz( key: key + "\\suite", item: "Version" );
	if(caissVer){
		set_kb_item( name: "CA/Multiple_Products/Win/Installed", value: TRUE );
		set_kb_item( name: "CA/ISS/Win/Ver", value: caissVer );
		register_and_report_cpe( app: caissName, ver: caissVer, base: "cpe:/a:ca:internet_security_suite:", expr: "^([0-9.]+)" );
	}
}
key = "SOFTWARE\\CA\\HIPSEngine";
cahipsVer = registry_get_sz( key: key, item: "Version" );
if(cahipsVer){
	set_kb_item( name: "CA/Multiple_Products/Win/Installed", value: TRUE );
	set_kb_item( name: "CA/HIPS/Engine/Win/Ver", value: cahipsVer );
	log_message( data: "CA HIPS Engine version " + cahipsVer + " was detected on the host" );
}
if(registry_key_exists( key: "SOFTWARE\\CA\\HIPSManagementServer" )){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	if(registry_key_exists( key: key )){
		for item in registry_enum_keys( key: key ) {
			name = registry_get_sz( key: key + item, item: "DisplayName" );
			if(eregmatch( pattern: "^CA HIPS Management Server", string: name )){
				hipsVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
				if(hipsVer){
					set_kb_item( name: "CA/Multiple_Products/Win/Installed", value: TRUE );
					set_kb_item( name: "CA/HIPS/Server/Win/Ver", value: hipsVer );
					log_message( data: "CA HIPS Management Server version " + hipsVer + " was detected on the host" );
				}
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(registry_key_exists( key: key )){
	for item in registry_enum_keys( key: key ) {
		if(ContainsString( registry_get_sz( key: key + item, item: "DisplayName" ), "CA Gateway Security" )){
			cagsPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			cagsPath = cagsPath + "Bin";
			cagsVer = fetch_file_version( sysPath: cagsPath, file_name: "ManagerConsole.exe" );
			if(cagsVer){
				set_kb_item( name: "CA/Multiple_Products/Win/Installed", value: TRUE );
				set_kb_item( name: "CA/Gateway-Security/Win/Ver", value: cagsVer );
				register_and_report_cpe( app: "CA Gateway Security", ver: cagsVer, base: "cpe:/a:ca:gateway_security:", expr: "^([0-9.]+)" );
			}
		}
	}
}

