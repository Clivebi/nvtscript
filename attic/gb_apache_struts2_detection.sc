if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107006" );
	script_version( "2021-04-01T11:05:36+0000" );
	script_tag( name: "last_modification", value: "2021-04-01 11:05:36 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-06-01 06:40:16 +0200 (Wed, 01 Jun 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Default Apache Struts2 Web Applications Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_tag( name: "summary", value: "HTTP based detection of Default Apache Struts2 Web
  Applications.

  The functionality of this VT has been merged into the VT 'Apache Struts Detection
  (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.800276)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

