if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12249" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "ReadDesign checker" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Net-Square Solutions Pvt Ltd." );
	script_family( "Web application abuses" );
	script_xref( name: "URL", value: "https://www.appsecinc.com/Policy/PolicyCheck1520.html" );
	script_tag( name: "summary", value: "This plugin checks for ReadDesign vulns on the remote web server." );
	script_tag( name: "impact", value: "Specifically, configuration information may be leaked which would aid
  an attacker in future exploits" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution", value: "See the references for a possible mitigation." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

