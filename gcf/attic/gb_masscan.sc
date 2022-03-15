if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105924" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-10-07 11:55:49 +0700 (Tue, 07 Oct 2014)" );
	script_name( "masscan (NASL wrapper)" );
	script_category( ACT_SCANNER );
	script_family( "Port scanners" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_tag( name: "summary", value: "This VT is deprecated." );
	script_tag( name: "qod_type", value: "remote_probe" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

