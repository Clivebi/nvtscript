if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105058" );
	script_version( "2021-09-16T12:48:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:48:59 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-07-07 10:42:27 +0200 (Mon, 07 Jul 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ESXi Authorization" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Credentials" );
	script_add_preference( name: "ESXi login name:", type: "entry", value: "", id: 1 );
	script_add_preference( name: "ESXi login password:", type: "password", value: "", id: 2 );
	script_tag( name: "summary", value: "This VT allows users to enter the information required to
  authorize and login into the ESXi SOAP API via HTTP.

  This information is used by tests that require authentication." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
esxi_login = script_get_preference( name: "ESXi login name:", id: 1 );
esxi_password = script_get_preference( name: "ESXi login password:", id: 2 );
if(esxi_login){
	set_kb_item( name: "esxi/login_filled/0", value: esxi_login );
}
if(esxi_password){
	set_kb_item( name: "esxi/password_filled/0", value: esxi_password );
}
exit( 0 );

