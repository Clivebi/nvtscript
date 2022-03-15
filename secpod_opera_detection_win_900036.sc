if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900036" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Opera Version Detection for Windows" );
	script_tag( name: "summary", value: "Detects the installed version of Opera on Windows.

  The script logs in via smb, searches for Opera in the registry and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
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
operaflag = TRUE;
func OperaSet( operaVersion, operaName, operaPath ){
	tmp_location = tolower( operaPath );
	tmp_location = ereg_replace( pattern: "\\\\$", string: tmp_location, replace: "" );
	set_kb_item( name: "Opera/Win/InstallLocations", value: tmp_location );
	set_kb_item( name: "Opera/Win/InstallLocations", value: tmp_location + "\\" + operaVersion );
	set_kb_item( name: "Opera/Build/Win/Ver", value: operaVersion );
	ver = eregmatch( pattern: "^([0-9]+\\.[0-9]+)", string: operaVersion );
	if(!isnull( ver[1] )){
		set_kb_item( name: "Opera/Win/Version", value: ver[1] );
		cpe = build_cpe( value: ver[1], exp: "^([0-9.]+)", base: "cpe:/a:opera:opera_browser:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:opera:opera_browser";
		}
		register_product( cpe: cpe, location: operaPath );
		log_message( data: build_detection_report( app: operaName, version: ver[1], install: operaPath, cpe: cpe, concluded: operaVersion ) );
	}
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_root = "SOFTWARE\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_root = "SOFTWARE\\Wow6432Node\\";
	}
}
key = key_root + "Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	operaName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(IsMatchRegexp( operaName, "^Opera " )){
		operaPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if( operaPath ){
			operaVer = fetch_file_version( sysPath: operaPath, file_name: "opera.exe" );
			if( operaVer ){
				OperaSet( operaVersion: operaVer, operaName: operaName, operaPath: operaPath );
				operaflag = FALSE;
			}
			else {
				operaVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
				if(operaVer){
					OperaSet( operaVersion: operaVer, operaName: operaName, operaPath: operaPath );
					operaflag = FALSE;
				}
			}
		}
		else {
			operaPath = registry_get_sz( key: key_root + "Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
			if(operaPath){
				operaPath = operaPath + "\\Opera";
				operaVer = fetch_file_version( sysPath: operaPath, file_name: "opera.exe" );
				if(operaVer){
					OperaSet( operaVersion: operaVer, operaName: operaName, operaPath: operaPath );
					operaflag = FALSE;
				}
			}
		}
	}
}
if(operaflag){
	operaPath = registry_get_sz( key: key_root + "Netscape\\Netscape Navigator\\5.0, Opera\\Main", item: "Install Directory" );
	if(operaPath){
		operaPath += "\\Opera";
		operaVer = fetch_file_version( sysPath: operaPath, file_name: "opera.exe" );
		if(operaVer){
			OperaSet( operaVersion: operaVer, operaName: "Opera", operaPath: operaPath );
		}
	}
}

