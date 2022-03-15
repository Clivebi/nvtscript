if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800984" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Symantec Altiris Notification Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of Symantec Altiris
  Notification Server." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Altiris" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	altirisName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( altirisName, "Altiris Notification Server" )){
		altirisVer1 = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(altirisVer1 != NULL){
			set_kb_item( name: "Symantec/AltirisNS/Ver", value: altirisVer1 );
			log_message( data: "Symantec Altiris Notification Server version " + altirisVer1 + " was detected on the host" );
		}
	}
	if(ContainsString( altirisName, "Altiris NS" )){
		altirisVer2 = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(altirisVer2 != NULL){
			set_kb_item( name: "Symantec/AltirisNS/SP", value: altirisVer2 );
			log_message( data: "Symantec Altiris Notification Server version " + altirisVer2 + " was detected on the host" );
		}
	}
}

