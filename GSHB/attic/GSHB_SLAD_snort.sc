if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96095" );
	script_version( "2021-08-09T13:51:37+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 13:51:37 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-12-01 10:53:45 +0100 (Wed, 01 Dec 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SLAD snort" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_tag( name: "summary", value: "This script connects to SLAD on a remote host to fetch the SNORT results.
To work properly, this script requires to be provided
with a valid SSH login by means of an SSH key with pass-
phrase if the SSH public key is passphrase-protected, or
a password to log in." );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
exit( 66 );

