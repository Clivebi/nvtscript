if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11022" );
	script_version( "2021-04-15T08:06:51+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 08:06:51 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "eDonkey/eMule Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Product detection" );
	script_tag( name: "summary", value: "eDonkey might be running on this port. This peer to peer
  software is used to share files.

  This VT has been deprecated and is therefore no longer functional." );
	script_tag( name: "vuldetect", value: "This script only checks if ports 4661-4663 are open and are
  unknown services." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

