if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901021" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "WinRAR Version Detection" );
	script_tag( name: "summary", value: "This script finds the installed WinRAR.

  The script logs in via smb, searches for WinRAR in the registry and gets the version." );
	script_category( ACT_GATHER_INFO );
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
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\WinRAR.exe" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\WinRAR.exe",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\WinRAR.exe" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
checkduplicate = "";
checkduplicate_path = "";
for key in key_list {
	rarPath = registry_get_sz( key: key, item: "Path" );
	if(ContainsString( rarPath, "WinRAR" )){
		rarVer = fetch_file_version( sysPath: rarPath, file_name: "WinRAR.exe" );
		if(isnull( rarVer )){
			path = rarPath + "\\WhatsNew.txt";
			rarVer = smb_read_file( fullpath: path, offset: 0, count: 1000 );
			if(rarVer){
				rarVer = eregmatch( pattern: "[v|V]ersion ([0-9.]+)", string: rarVer );
				if(rarVer[1]){
					rarVer = rarVer[1];
				}
			}
		}
		if(ContainsString( checkduplicate, rarVer + ", " ) && ContainsString( checkduplicate_path, rarPath + ", " )){
			continue;
		}
		checkduplicate += rarVer + ", ";
		checkduplicate_path += rarPath + ", ";
		set_kb_item( name: "WinRAR/Ver", value: rarVer );
		cpe = build_cpe( value: rarVer, exp: "^([0-9.]+)", base: "cpe:/a:rarlab:winrar:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:rarlab:winrar";
		}
		if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) && !ContainsString( rarPath, "x86" )){
			set_kb_item( name: "WinRAR64/Ver", value: rarVer );
			cpe = build_cpe( value: rarVer, exp: "^([0-9.]+)", base: "cpe:/a:rarlab:winrar:x64:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:rarlab:winrar:x64";
			}
		}
		register_product( cpe: cpe, location: rarPath );
		log_message( data: build_detection_report( app: "WinRar", version: rarVer, install: rarPath, cpe: cpe, concluded: rarVer ) );
	}
}

