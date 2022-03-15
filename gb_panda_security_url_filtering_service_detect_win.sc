if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809036" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-12-14 19:02:08 +0530 (Wed, 14 Dec 2016)" );
	script_name( "Panda Security URL Filtering Service Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Panda Security URL Filtering Service.

  The script logs in via smb, searches for executable of
  Panda Security URL Filtering 'Panda_URL_Filteringb.exe' and gets the file
  version." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Panda Software" ) && !registry_key_exists( key: "SOFTWARE\\panda_url_filtering" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Panda Software" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\panda_url_filtering" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Panda Security URL Filtering";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Panda Security URL Filtering";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
pandaurlPath = registry_get_sz( item: "InstallLocation", key: key );
if(!pandaurlPath){
	exit( 0 );
}
pandaurlVer = fetch_file_version( sysPath: pandaurlPath, file_name: "\\Panda_URL_Filteringb.exe" );
if(pandaurlVer){
	set_kb_item( name: "PandaSecurity/URL/Filtering/Win/Ver", value: pandaurlVer );
	cpe = build_cpe( value: pandaurlVer, exp: "^([0-9.]+)", base: "cpe:/a:pandasecurity:panda_security_url_filtering:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:pandasecurity:panda_security_url_filtering";
	}
	register_product( cpe: cpe, location: pandaurlPath );
	log_message( data: build_detection_report( app: "Panda Security URL Filtering", version: pandaurlVer, install: pandaurlPath, cpe: cpe, concluded: pandaurlVer ) );
}

