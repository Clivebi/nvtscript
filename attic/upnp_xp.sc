if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10829" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3723 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0876" );
	script_name( "scan for UPNP hosts" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 by John Lampe" );
	script_family( "Windows" );
	script_xref( name: "URL", value: "http://grc.com/UnPnP/UnPnP.htm" );
	script_tag( name: "summary", value: "Microsoft Universal Plug n Play is running on this machine. This service is dangerous for many
  different reasons." );
	script_tag( name: "solution", value: "To disable UPNP see the references." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

