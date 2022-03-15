if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96210" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-05-25 14:26:00 +0200 (Wed, 25 May 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Check for File Policy Violations" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_tag( name: "summary", value: "Check for File Policy Violations

  ATTENTION: This NVT is deprecated. Please use the new set of 4 NVTs to handle
  file policies which are to be found in the family 'Policy'." );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
exit( 66 );

