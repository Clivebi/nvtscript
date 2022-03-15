if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103591" );
	script_version( "2021-05-12T09:44:59+0000" );
	script_tag( name: "last_modification", value: "2021-05-12 09:44:59 +0000 (Wed, 12 May 2021)" );
	script_tag( name: "creation_date", value: "2012-10-24 10:55:52 +0100 (Wed, 24 Oct 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SSH Authorization" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Credentials" );
	script_add_preference( name: "Keys:", type: "sshlogin", value: "-", id: 5 );
	script_add_preference( name: "SSH login name:", type: "entry", value: "", id: 1 );
	script_add_preference( name: "SSH password (unsafe!):", type: "password", value: "", id: 3 );
	script_add_preference( name: "SSH public key:", type: "file", value: "", id: 6 );
	script_add_preference( name: "SSH private key:", type: "file", value: "", id: 4 );
	script_add_preference( name: "SSH key passphrase:", type: "password", value: "", id: 2 );
	script_add_preference( name: "SSH privilege login name:", type: "entry", value: "", id: 7 );
	script_add_preference( name: "SSH privilege password:", type: "password", value: "", id: 8 );
	script_tag( name: "summary", value: "This script allows users to enter the information
  required to authorize and login via ssh protocol.

  These data will be used by other tests to executed authenticated checks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
ssh_login_name = script_get_preference( name: "SSH login name:", id: 1 );
ssh_password = script_get_preference( name: "SSH password (unsafe!):", id: 3 );
ssh_public_key = script_get_preference_file_content( name: "SSH public key:", id: 6 );
ssh_private_key = script_get_preference_file_content( name: "SSH private key:", id: 4 );
ssh_key_passphrase = script_get_preference( name: "SSH key passphrase:", id: 2 );
ssh_priv_login = script_get_preference( name: "SSH privilege login name:", id: 7 );
ssh_priv_password = script_get_preference( name: "SSH privilege password:", id: 8 );
if(ssh_login_name){
	set_kb_item( name: "Secret/SSH/login", value: ssh_login_name );
}
if(ssh_password){
	set_kb_item( name: "Secret/SSH/password", value: ssh_password );
}
if(ssh_public_key){
	set_kb_item( name: "Secret/SSH/publickey", value: ssh_public_key );
}
if(ssh_private_key){
	set_kb_item( name: "Secret/SSH/privatekey", value: ssh_private_key );
}
if(ssh_key_passphrase){
	set_kb_item( name: "Secret/SSH/passphrase", value: ssh_key_passphrase );
}
if(ssh_priv_login){
	set_kb_item( name: "Secret/SSH/privlogin", value: ssh_priv_login );
}
if(ssh_priv_password){
	set_kb_item( name: "Secret/SSH/privpassword", value: ssh_priv_password );
}
exit( 0 );

