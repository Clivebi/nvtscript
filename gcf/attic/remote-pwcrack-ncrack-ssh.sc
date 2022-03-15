if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80105" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-08-10 08:41:48 +0200 (Mon, 10 Aug 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "ncrack: SSH" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Vlatko Kosturjak" );
	script_family( "Brute force attacks" );
	script_tag( name: "summary", value: "This VT is deprecated." );
	script_tag( name: "solution", value: "Set a secure password for the mentioned account(s)." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

