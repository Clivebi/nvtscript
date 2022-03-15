if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103583" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-10-10 11:28:02 +0200 (Wed, 10 Oct 2012)" );
	script_name( "Siemens SIMATIC S7-1200 PLC Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_tag( name: "summary", value: "Detection of Siemens SIMATIC S7-1200 PLC.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.

  This NVT has been replaced by NVTs gb_simatic_s7_version.nasl (OID:1.3.6.1.4.1.25623.1.0.106096)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

