if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901174" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "OpenSC Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version of OpenSC on Windows." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!osArch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\OpenSC Project\\OpenSC" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\OpenSC Project\\OpenSC" )){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(!key_list){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( name, "OpenSC" )){
			concluded = name;
			if(!ver = registry_get_sz( key: key + item, item: "DisplayVersion" )){
				ver = "unknown";
			}
			set_kb_item( name: "opensc/win/detected", value: TRUE );
			if( ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
				set_kb_item( name: "opensc64/win/detected", value: TRUE );
				register_and_report_cpe( app: "OpenSC", ver: ver, concluded: concluded, base: "cpe:/a:opensc-project:opensc:x64:", expr: "^([0-9.]+)", regService: "smb-login", regPort: 0 );
			}
			else {
				register_and_report_cpe( app: "OpenSC", ver: ver, concluded: concluded, base: "cpe:/a:opensc-project:opensc:", expr: "^([0-9.]+)", regService: "smb-login", regPort: 0 );
			}
		}
	}
}
exit( 0 );

