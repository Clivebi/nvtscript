if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800096" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-06-02 09:27:25 +0200 (Tue, 02 Jun 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Merak Mail Server Web Mail Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_tag( name: "summary", value: "Detection of Merak Mail Server Web Mail.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.

  This NVT has been replaced by gb_icewarp_web_detect.nasl (1.3.6.1.4.1.25623.1.0.140329) and
  gb_icewarp_mail_detect.nasl (1.3.6.1.4.1.25623.1.0.140330)." );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
exit( 66 );

