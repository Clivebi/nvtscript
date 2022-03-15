if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803511" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:00 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: auth-spoof" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Checks for an identd (auth)server which is spoofing its replies.

  Tests whether an identd (auth) server responds with an answer before we even send the query. This
  sort of identd spoofing can be a sign of malware infection, though it can also be used for
  legitimate privacy reasons." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

