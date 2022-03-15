if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810550" );
	script_version( "$Revision: 10911 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-14 15:12:01 +0530 (Tue, 14 Feb 2017)" );
	script_name( "SMBv1 Client Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detecting if SMBv1 is enabled for the SMB Client
  or not.

  The script logs in via SMB, searches for key specific to the SMB Client
  in the registry and gets the value from the 'Start' string." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
key1 = "SYSTEM\\CurrentControlSet\\Services\\mrxsmb10";
key2 = "SYSTEM\\ControlSet001\\Services\\mrxsmb10";
if(!registry_key_exists( key: key1 ) && !registry_key_exists( key: key2 )){
	exit( 0 );
}
smb1_value1 = registry_get_dword( item: "Start", key: key1 );
if(!smb1_value1){
	smb1_value2 = registry_get_dword( item: "Start", key: key2 );
}
if(smb1_value1 == 2 || smb1_value2 == 2){
	set_kb_item( name: "smb_v1_client/enabled", value: TRUE );
	set_kb_item( name: "smb_v1/enabled", value: TRUE );
	report = "SMBv1 is enabled for the SMB Client";
	log_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

