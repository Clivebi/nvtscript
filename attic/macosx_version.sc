if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102005" );
	script_version( "2021-03-04T11:38:37+0000" );
	script_tag( name: "last_modification", value: "2021-03-04 11:38:37 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2009-11-17 12:37:40 +0100 (Tue, 17 Nov 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Mac OS X Version" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 LSS" );
	script_tag( name: "summary", value: "This script gets the Mac OS X version from other plugins and reports if the
  host is running an outdated/unsupported version.

  This VT has been replaced by the VT 'OS End Of Life Detection' (OID: 1.3.6.1.4.1.25623.1.0.103674)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

