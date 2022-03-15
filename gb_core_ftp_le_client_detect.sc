if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810304" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-12-08 11:49:16 +0530 (Thu, 08 Dec 2016)" );
	script_name( "Core FTP LE Client Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Core FTP LE Client.

  The script logs in via smb, searches for 'Core FTP LE' in the
  registry, gets version and installation path information from the registry." );
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
for item in registry_enum_keys( key: key ) {
	ftpName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( ftpName, "Core FTP LE" )){
		ftpPath = registry_get_sz( key: key + item, item: "UninstallString" );
		if( ftpPath ){
			ftpPath = ftpPath - "uninstall.exe";
			ftpPath = ereg_replace( pattern: "\"", replace: "", string: ftpPath );
			ftpVer = fetch_file_version( sysPath: ftpPath, file_name: "coreftp.exe" );
		}
		else {
			ftpPath = "Couldn find the install location";
		}
		if(ftpVer){
			set_kb_item( name: "Core/FTP/Client/Win/Ver", value: ftpVer );
			cpe = build_cpe( value: ftpVer, exp: "^([0-9.]+)", base: "cpe:/a:coreftp:core_ftp:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:coreftp:core_ftp";
			}
			register_product( cpe: cpe, location: ftpPath );
			log_message( data: build_detection_report( app: "Core FTP LE", version: ftpVer, install: ftpPath, cpe: cpe, concluded: ftpVer ) );
		}
	}
}

