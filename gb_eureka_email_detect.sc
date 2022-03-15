if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801040" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Eureka Email Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of Eureka Email." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Eureka Email Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	eeName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( eeName, "Eureka Email" )){
		eePath = registry_get_sz( key: key + item, item: "Inno Setup: App Path" );
		if(eePath){
			eePath += "\\Eureka Email.EXE";
			share = ereg_replace( pattern: "([A-Za-z]):.*", replace: "\\1$", string: eePath );
			file = ereg_replace( pattern: "[A-Za-z]:(.*)", replace: "\\1", string: eePath );
			eeVer = GetVer( file: file, share: share );
			if(eeVer != NULL){
				set_kb_item( name: "EurekaEmail/Ver", value: eeVer );
				log_message( data: "Eureka Email version " + eeVer + " was detected on the host" );
				cpe = build_cpe( value: eeVer, exp: "^([0-9.]+)", base: "cpe:/a:eureka-email:eureka_email:" );
				if(!isnull( cpe )){
					register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
				}
			}
		}
	}
}

