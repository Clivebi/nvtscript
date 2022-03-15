if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810549" );
	script_version( "2020-08-14T11:44:26+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-14 11:44:26 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-02-14 15:12:01 +0530 (Tue, 14 Feb 2017)" );
	script_name( "SMBv1 Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detecting if SMBv1 is enabled for the SMB Server
  or not.

  The script logs in via SMB, searches for key specific to the SMB Server
  in the registry and gets the value from the 'SMB1' string." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
key1 = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";
key2 = "SYSTEM\\ControlSet001\\Services\\LanmanServer\\Parameters";
if(!registry_key_exists( key: key1 ) && !registry_key_exists( key: key2 )){
	exit( 0 );
}
smb1_value1 = registry_get_dword( item: "SMB1", key: key1 );
smb1_value2 = registry_get_dword( item: "SMB1", key: key2 );
if( smb1_value1 == 1 || smb1_value2 == 1 ){
	smbv1_enabled = TRUE;
}
else {
	if(smb1_value1 == "" && smb1_value2 == ""){
		key1 = "SYSTEM\\CurrentControlSet\\Services\\srv";
		key2 = "SYSTEM\\ControlSet001\\Services\\srv";
		if(registry_key_exists( key: key1 ) || registry_key_exists( key: key2 )){
			smbv1_enabled = TRUE;
		}
	}
}
if(smbv1_enabled){
	set_kb_item( name: "smb_v1_server/enabled", value: TRUE );
	set_kb_item( name: "smb_v1/enabled", value: TRUE );
	report = "SMBv1 is enabled for the SMB Server";
	log_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

