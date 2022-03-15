if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103697" );
	script_version( "2019-11-13T14:31:51+0000" );
	script_tag( name: "last_modification", value: "2019-11-13 14:31:51 +0000 (Wed, 13 Nov 2019)" );
	script_tag( name: "creation_date", value: "2013-04-15 10:23:42 +0200 (Mon, 15 Apr 2013)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Options for Brute Force NVTs" );
	script_category( ACT_SETTINGS );
	script_family( "Settings" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_add_preference( name: "Credentials file:", value: "", type: "file" );
	script_add_preference( name: "Use only credentials listed in uploaded file:", type: "checkbox", value: "yes" );
	script_add_preference( name: "Disable brute force checks", type: "checkbox", value: "no" );
	script_add_preference( name: "Disable default account checks", type: "checkbox", value: "no" );
	script_tag( name: "summary", value: "This VT sets some options for the brute force credentials checks.

  - Disable brute force checks:

  Disables the brute force checks done by the following VTs:

  HTTP Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108041)

  SSH Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108013)

  SMB Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.804449)

  Check default community names of the SNMP Agent (OID: 1.3.6.1.4.1.25623.1.0.103914).

  - Disable default account checks:

  Disables all VTs checking for default accounts (Mainly from the 'Default Accounts' family).

  - Credentials file:

  A file containing a list of credentials. One username/password pair per line. Username and password are separated
  by ':'. Please use 'none' for empty passwords or empty usernames. If the username or the password contains a ':',
  please escape it with '\\:'.

  Examples:

  user:userpass

  user1:userpass1

  none:userpass2

  user3:none

  user4:pass\\:word

  user5:userpass5

  - Use only credentials listed in uploaded file:

  Use only the credentials that are listed in the uploaded file. The internal default credentials are ignored." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
disable_bf = script_get_preference( "Disable brute force checks" );
if(ContainsString( disable_bf, "yes" )){
	set_kb_item( name: "default_credentials/disable_brute_force_checks", value: TRUE );
}
disable_da = script_get_preference( "Disable default account checks" );
if(ContainsString( disable_da, "yes" )){
	set_kb_item( name: "default_credentials/disable_default_account_checks", value: TRUE );
}
credentials_list = script_get_preference_file_content( "Credentials file:" );
if(!credentials_list){
	exit( 0 );
}
credentials_lines = split( buffer: credentials_list, keep: FALSE );
for line in credentials_lines {
	if(!IsMatchRegexp( line, "^.+;.+$" ) && !IsMatchRegexp( line, "^.+:.+$" )){
		log_message( port: 0, data: "Invalid line " + line + " in uploaded credentials file. Scanner will not use this line." );
		continue;
	}
	set_kb_item( name: "default_credentials/credentials", value: line + ":custom:all" );
}
uploaded_credentials_only = script_get_preference( "Use only credentials listed in uploaded file:" );
set_kb_item( name: "default_credentials/uploaded_credentials_only", value: uploaded_credentials_only );
exit( 0 );

