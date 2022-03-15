if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900961" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "FTPShell Client Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of FTPShell Client" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		fcName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( fcName, "FTPShell Client" )){
			fcPath = registry_get_sz( key: key + item, item: "UninstallString" );
			fcPath = ereg_replace( pattern: "\"(.*)\"", replace: "\\1", string: fcPath );
			fcPath = fcPath - "unins000.exe" + "readme.txt";
			if(fcPath){
				readmeText = smb_read_file( fullpath: fcPath, offset: 0, count: 500 );
				if(readmeText){
					fcVer = eregmatch( pattern: "Version +: ([0-9.]+).?([a-zA-Z]+.?[0-9]+)?", string: readmeText );
					if(!isnull( fcVer[1] )){
						if( !isnull( fcVer[2] ) ){
							fcVer[2] = ereg_replace( pattern: " ", string: fcVer[2], replace: "" );
							fcVer = fcVer[1] + "." + fcVer[2];
						}
						else {
							fcVer = fcVer[1];
						}
					}
				}
			}
			if(isnull( fcVer )){
				fcVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
				fcPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!fcPath){
					fcPath = "Unable to find the install location from registry";
				}
			}
			if(fcVer){
				set_kb_item( name: "FTPShell/Client/Ver", value: fcVer );
				cpe = build_cpe( value: fcVer, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:ftpshell:ftpshell:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:ftpshell:ftpshell";
				}
				if(ContainsString( os_arch, "x64" ) && !ContainsString( fcPath, "x86" )){
					set_kb_item( name: "FTPShell/Client64/Win/Ver", value: fcVer );
					cpe = build_cpe( value: fcVer, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:ftpshell:ftpshell:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:ftpshell:ftpshell:x64";
					}
				}
				register_product( cpe: cpe, location: fcPath );
				log_message( data: build_detection_report( app: "FTPShell Client", version: fcVer, install: fcPath, cpe: cpe, concluded: fcVer ) );
			}
		}
	}
}

