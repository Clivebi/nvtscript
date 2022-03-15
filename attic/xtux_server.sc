if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11016" );
	script_version( "2021-04-15T08:06:51+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 08:06:51 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "xtux Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_tag( name: "summary", value: "The xtux server might be running on this port. If somebody
  connects to it and sends it garbage data, it may loop and overload your CPU.

  This VT has been deprecated and is therefore no longer functional." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

