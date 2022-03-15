if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801224" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)" );
	script_name( "Adobe Photoshop Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe
  Photoshop on Windows.

  The script logs in via smb, searches for Adobe Photoshop and gets the
  version from 'Version' string in registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
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
appkey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Photoshop.exe";
if(!registry_key_exists( key: appkey )){
	appkey = "SOFTWARE\\Wow6432Node\\Windows\\CurrentVersion\\App Paths\\Photoshop.exe";
	if(!registry_key_exists( key: appkey )){
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
appPath = registry_get_sz( key: appkey, item: "Path" );
if(appPath){
	photoVer = fetch_file_version( sysPath: appPath, file_name: "Photoshop.exe" );
	if(!photoVer){
		exit( 0 );
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
checkduplicate = "";
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(!ContainsString( appName, "Photoshop" )){
		continue;
	}
	if( ContainsString( appName, "Adobe Photoshop CS" ) ){
		ver = eregmatch( pattern: "CS([0-9.]+)", string: appName );
		if(ver[0]){
			tmp_version = ver[0] + " " + photoVer;
			if(ContainsString( checkduplicate, tmp_version + ", " )){
				continue;
			}
			checkduplicate += tmp_version + ", ";
			set_kb_item( name: "Adobe/Photoshop/Installed", value: TRUE );
			if( ContainsString( os_arch, "x64" ) && ContainsString( appPath, "64 Bit" ) ){
				set_kb_item( name: "Adobe/Photoshop64/Ver", value: tmp_version );
				register_and_report_cpe( app: appName, ver: photoVer, concluded: tmp_version, base: "cpe:/a:adobe:photoshop_cs" + ver[1] + ":x64:", expr: "^([0-9.]+)", insloc: appPath );
			}
			else {
				set_kb_item( name: "Adobe/Photoshop/Ver", value: tmp_version );
				register_and_report_cpe( app: appName, ver: photoVer, concluded: tmp_version, base: "cpe:/a:adobe:photoshop_cs" + ver[1] + ":", expr: "^([0-9.]+)", insloc: appPath );
			}
		}
	}
	else {
		if( ContainsString( appName, "Adobe Photoshop CC" ) ){
			prodVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			ver = eregmatch( pattern: "CC.([0-9.]+)", string: appName );
			if(ver[0]){
				tmp_version = ver[0] + " " + photoVer;
				if(ContainsString( checkduplicate, tmp_version + ", " )){
					continue;
				}
				checkduplicate += tmp_version + ", ";
				set_kb_item( name: "Adobe/Photoshop/ProdVer", value: prodVer );
				set_kb_item( name: "Adobe/Photoshop/Installed", value: TRUE );
				if( ContainsString( os_arch, "x64" ) && ContainsString( appPath, "64 Bit" ) ){
					set_kb_item( name: "Adobe/Photoshop64/Ver", value: tmp_version );
					register_and_report_cpe( app: appName, ver: photoVer, concluded: tmp_version, base: "cpe:/a:adobe:photoshop_cc" + ver[1] + ":x64:", expr: "^([0-9.]+)", insloc: appPath );
				}
				else {
					set_kb_item( name: "Adobe/Photoshop/Ver", value: tmp_version );
					register_and_report_cpe( app: appName, ver: photoVer, concluded: tmp_version, base: "cpe:/a:adobe:photoshop_cc" + ver[1] + ":", expr: "^([0-9.]+)", insloc: appPath );
				}
			}
		}
		else {
			if(ContainsString( appName, "Adobe Photoshop" )){
				if(ContainsString( checkduplicate, photoVer + ", " )){
					continue;
				}
				checkduplicate += photoVer + ", ";
				set_kb_item( name: "Adobe/Photoshop/Installed", value: TRUE );
				if( ContainsString( os_arch, "x64" ) && ContainsString( appPath, "64 Bit" ) ){
					set_kb_item( name: "Adobe/Photoshop64/Ver", value: photoVer );
					register_and_report_cpe( app: appName, ver: photoVer, concluded: photoVer, base: "cpe:/a:adobe:photoshop:x64:", expr: "^([0-9.]+)", insloc: appPath );
				}
				else {
					set_kb_item( name: "Adobe/Photoshop/Ver", value: photoVer );
					register_and_report_cpe( app: appName, ver: photoVer, concluded: photoVer, base: "cpe:/a:adobe:photoshop:", expr: "^([0-9.]+)", insloc: appPath );
				}
			}
		}
	}
}

