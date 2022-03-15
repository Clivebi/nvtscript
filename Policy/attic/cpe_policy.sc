if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100353" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "CPE-based Policy Check" );
	script_category( ACT_END );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "summary", value: "This NVT is running CPE-based Policy Checks.

  ATTENTION: This NVT is deprecated. Please use the new set of 4 NVTs to handle
  CPE policies which are to be found in the family 'Policy'." );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "qod_type", value: "general_note" );
	exit( 0 );
}
exit( 66 );

