if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80009" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-10-26 10:11:20 +0100 (Sun, 26 Oct 2008)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "strobe (NASL wrapper)" );
	script_category( ACT_SCANNER );
	script_copyright( "Copyright (C) 2008-2010 Vlatko Kosturjak" );
	script_family( "Port scanners" );
	script_tag( name: "summary", value: "This VT is deprecated." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

