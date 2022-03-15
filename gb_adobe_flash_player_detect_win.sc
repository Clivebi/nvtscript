if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800029" );
	script_version( "2021-02-08T13:19:59+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-08 13:19:59 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)" );
	script_name( "Adobe Flash Player/Flash CS/AIR/Flex Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_tag( name: "summary", value: "SMB login-based detection of Adobe Flash Player/Flash CS/AIR/Flex." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
checkduplicate = "";
checkduplicate_path = "";
airFlag = 0;
csFlag = 0;
playerFlag = 0;
flexFlag = 0;
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		adobeName = registry_get_sz( key: key + item, item: "DisplayName" );
		if( ContainsString( adobeName, "Adobe AIR" ) && airFlag == 0 ){
			airVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!isnull( airVer )){
				if(ContainsString( checkduplicate, airVer + ", " ) && ContainsString( checkduplicate_path, insPath + ", " )){
					continue;
				}
				checkduplicate += airVer + ", ";
				checkduplicate_path += insPath + ", ";
				set_kb_item( name: "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value: TRUE );
				set_kb_item( name: "Adobe/Air/Win/Installed", value: TRUE );
				if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "Adobe/Air64/Win/Ver", value: airVer );
					register_and_report_cpe( app: adobeName, ver: airVer, base: "cpe:/a:adobe:adobe_air:x64:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
				}
				else {
					set_kb_item( name: "Adobe/Air/Win/Ver", value: airVer );
					register_and_report_cpe( app: adobeName, ver: airVer, base: "cpe:/a:adobe:adobe_air:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
				}
			}
		}
		else {
			if( ContainsString( adobeName, "Adobe Flash CS" ) && csFlag == 0 ){
				fcsVer = eregmatch( pattern: "Flash (CS[0-9])", string: adobeName );
				insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!isnull( fcsVer[1] )){
					set_kb_item( name: "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value: TRUE );
					if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
						set_kb_item( name: "Adobe/FlashCS64/Win/Ver", value: fcsVer[1] );
						register_and_report_cpe( app: adobeName, ver: fcsVer[1], base: "cpe:/a:adobe:flash_cs:x64:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
					}
					else {
						set_kb_item( name: "Adobe/FlashCS/Win/Ver", value: fcsVer[1] );
						register_and_report_cpe( app: adobeName, ver: fcsVer[1], base: "cpe:/a:adobe:flash_cs:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
					}
				}
			}
			else {
				if( ContainsString( adobeName, "Adobe Flash Player" ) && playerFlag == 0 ){
					playerVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
					insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
					if(!insPath){
						insPath = registry_get_sz( key: key + item, item: "DisplayIcon" );
					}
					if(!insPath){
						insPath = "Could not find the install location from registry";
					}
					if(!isnull( playerVer )){
						set_kb_item( name: "adobe/flash_player/detected", value: TRUE );
						set_kb_item( name: "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value: TRUE );
						set_kb_item( name: "AdobeFlashPlayer/Win/Installed", value: TRUE );
						set_kb_item( name: "AdobeFlashPlayer/Win/Ver", value: playerVer );
						register_and_report_cpe( app: adobeName, ver: playerVer, base: "cpe:/a:adobe:flash_player:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
						if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
							set_kb_item( name: "AdobeFlashPlayer64/Win/Ver", value: playerVer );
							register_and_report_cpe( app: adobeName, ver: playerVer, base: "cpe:/a:adobe:flash_player:x64:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
						}
					}
				}
				else {
					if(ContainsString( adobeName, "Adobe Flex" ) && flexFlag == 0){
						flexVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
						insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
						if(!isnull( flexVer )){
							set_kb_item( name: "Adobe/Flex/Win/Installed", value: TRUE );
							if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
								set_kb_item( name: "Adobe/Flex64/Win/Ver", value: flexVer );
								register_and_report_cpe( app: adobeName, ver: flexVer, base: "cpe:/a:adobe:flex:x64:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
							}
							else {
								set_kb_item( name: "Adobe/Flex/Win/Ver", value: flexVer );
								register_and_report_cpe( app: adobeName, ver: flexVer, base: "cpe:/a:adobe:flex:", expr: "^([0-9.]+)", insloc: insPath, regPort: 0, regService: "smb-login" );
							}
						}
					}
				}
			}
		}
	}
}

