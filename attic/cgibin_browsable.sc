if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10039" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "/cgi-bin directory browsable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Hendrik Scholz" );
	script_family( "Web application abuses" );
	script_tag( name: "solution", value: "Make the /cgi-bin non-browsable." );
	script_tag( name: "summary", value: "The /cgi-bin directory is browsable.

  This NVT has been replaced by NVT 'Enabled Directory Listing Detection' (OID: 1.3.6.1.4.1.25623.1.0.111074)." );
	script_tag( name: "impact", value: "This will show you the name of the installed common scripts
  and those which are written by the webmaster and thus may be exploitable." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

