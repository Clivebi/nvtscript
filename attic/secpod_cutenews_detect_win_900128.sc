if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900128" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-03T08:47:58+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 08:47:58 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_name( "CuteNews Version Detection for Windows" );
	script_tag( name: "summary", value: "Deprecated: This NVT has been replaced by NVT 'CuteNews Detection' (OID:
  1.3.6.1.4.1.25623.1.0.100105).

  This script find the CuteNews installed version of Windows." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

