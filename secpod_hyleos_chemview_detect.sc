if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900748" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Hyleos ChemView Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed Hyleos ChemView." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Hyleos ChemView Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( name, "Hyleos - ChemViewX" )){
		chemVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(chemVer != NULL){
			set_kb_item( name: "Hyleos/ChemViewX/Ver", value: chemVer );
			log_message( data: "Hyleos ChemView version " + chemVer + " was detected on the host" );
			cpe = build_cpe( value: chemVer, exp: "^([0-9.]+)", base: "cpe:/a:hyleos:chemview:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

