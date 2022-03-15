if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96195" );
	script_version( "$Revision: 11584 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-25 09:02:39 +0200 (Tue, 25 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-09-08 13:13:43 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Check for Windows 10 Cortana Search" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Check for Windows 10 Cortana Search" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("smb_nt.inc.sc");
CurrentMajorVersionNumber = registry_get_dword( key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", item: "CurrentMajorVersionNumber" );
if(!CurrentMajorVersionNumber || CurrentMajorVersionNumber < 10){
	exit( 0 );
}
cortanaEnabled = FALSE;
key1 = "SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Experience";
key2 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search";
key3 = "SOFTWARE\\WOW6432Node\\Policies\\Microsoft\\Windows\\Windows Search";
if( !registry_key_exists( key: key1, type: "HKLM" ) && !registry_key_exists( key: key2, type: "HKLM" ) && !registry_key_exists( key: key3, type: "HKLM" ) ){
	cortanaEnabled = TRUE;
}
else {
	reskey1 = registry_get_dword( item: "AllowCortana", key: key1, type: "HKLM" );
	reskey2 = registry_get_dword( item: "AllowCortana", key: key2, type: "HKLM" );
	reskey3 = registry_get_dword( item: "AllowCortana", key: key3, type: "HKLM" );
	if(( isnull( reskey1 ) || reskey1 == "1" ) && ( isnull( reskey2 ) || reskey2 == "1" ) && ( isnull( reskey3 ) || reskey3 == "1" )){
		cortanaEnabled = TRUE;
	}
}
if(cortanaEnabled){
	log_message( port: 0, data: "Cortana Search is enabled." );
	exit( 0 );
}
exit( 99 );

