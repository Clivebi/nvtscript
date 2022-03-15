if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900712" );
	script_version( "2021-09-03T08:47:58+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 08:47:58 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "b2evolution Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_tag( name: "summary", value: "This script finds the installed b2evolution script version.

  This VT has been replaced by VT 'b2evolution CMS Detection' (OID: 1.3.6.1.4.1.25623.1.0.106534)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

