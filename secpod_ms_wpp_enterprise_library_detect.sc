if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900956" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Microsoft Windows Patterns & Practices EntLib Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed version of Microsoft Windows
  Patterns & Practices Enterprise Library." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Microsoft Windows Patterns and Practices EntLib Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	entlibName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( entlibName, "Enterprise Library" )){
		entlibVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!isnull( entlibVer )){
			set_kb_item( name: "MS/WPP/EntLib/Ver", value: entlibVer );
			log_message( data: "Microsoft Windows Patterns & Practices Enterprise " + "Library version " + entlibVer + " was detected on the host" );
			cpe = build_cpe( value: entlibVer, exp: "^([0-9]\\.[0-9])", base: "cpe:/a:microsoft:enterprise_library:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

