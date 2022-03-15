if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80005" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sybase Enterprise Application Server Management Console detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "general_note" );
	script_copyright( "Copyright (C) 2008 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Service detection" );
	script_tag( name: "solution", value: "It's recommended to allow connection to this host only from trusted host or networks,
  or disable the service if not used." );
	script_tag( name: "summary", value: "The remote host is running the Sybase Enterprise Application Server JSP Administration Console.
  Sybase EAServer is the open application server from Sybase Inc an enterprise software and services company,
  exclusively focused on managing and mobilizing information.

  This NVT was deprecated and the detection of the Server Management Console was moved to remote-detect-sybase-easerver.nasl" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

