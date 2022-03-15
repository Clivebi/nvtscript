if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902311" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "BlackBerry Desktop Software Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "This script detects the installed version of BlackBerry Desktop
  Software." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "BlackBerry Desktop Software Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	bbdName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( bbdName, "BlackBerry Desktop Software" )){
		bbdVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(bbdVer != NULL){
			set_kb_item( name: "BlackBerry/Desktop/Win/Ver", value: bbdVer );
			log_message( data: "BlackBerry Desktop Software version " + bbdVer + " was detected on the host" );
			cpe = build_cpe( value: bbdVer, exp: "^([0-9.]+)", base: "cpe:/a:rim:blackberry_desktop_software:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

