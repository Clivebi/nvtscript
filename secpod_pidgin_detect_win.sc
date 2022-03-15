if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900662" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Pidgin Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script detects the installed version of Pidgin on Windows.

The script logs in via smb, searches for Pidgin in the registry and gets the
Pidgin path and version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pidgin\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pidgin\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pidgin\\" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pidgin\\" )){
		exit( 0 );
	}
}
for key in key_list {
	pidginName = registry_get_sz( key: key, item: "DisplayName" );
	if(ContainsString( pidginName, "Pidgin" )){
		pidginPath = registry_get_sz( key: key, item: "UninstallString" );
		if( !pidginPath ){
			pidginPath = "Could not find the install location from registry";
		}
		else {
			pidginPath = pidginPath - "pidgin-uninst.exe";
		}
		pidginVer = registry_get_sz( key: key, item: "DisplayVersion" );
		if(pidginVer){
			set_kb_item( name: "Pidgin/Win/Ver", value: pidginVer );
			cpe = build_cpe( value: pidginVer, exp: "^([0-9.]+)", base: "cpe:/a:pidgin:pidgin:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:pidgin:pidgin";
			}
			register_product( cpe: cpe, location: pidginPath );
			log_message( data: build_detection_report( app: "Pidgin", version: pidginVer, install: pidginPath, cpe: cpe, concluded: pidginVer ) );
		}
	}
}

