if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.90023" );
	script_version( "2019-07-08T14:12:44+0000" );
	script_tag( name: "last_modification", value: "2019-07-08 14:12:44 +0000 (Mon, 08 Jul 2019)" );
	script_tag( name: "creation_date", value: "2008-06-02 00:42:27 +0200 (Mon, 02 Jun 2008)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SMB Authorization" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Credentials" );
	script_add_preference( name: "SMB login:", type: "entry", value: "", id: 1 );
	script_add_preference( name: "SMB password:", type: "password", value: "", id: 2 );
	script_add_preference( name: "SMB domain (optional):", type: "entry", value: "", id: 3 );
	script_tag( name: "summary", value: "This script allows users to enter the information
  required to authorize and login via SMB.

  These data are used by tests that require authentication." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
smb_login = script_get_preference( name: "SMB login:", id: 1 );
smb_password = script_get_preference( name: "SMB password:", id: 2 );
smb_domain = script_get_preference( name: "SMB domain (optional):", id: 3 );
if(smb_login){
	set_kb_item( name: "SMB/login_filled/0", value: smb_login );
}
if(smb_password){
	set_kb_item( name: "SMB/password_filled/0", value: smb_password );
}
if(smb_domain){
	set_kb_item( name: "SMB/domain_filled/0", value: smb_domain );
}
exit( 0 );

