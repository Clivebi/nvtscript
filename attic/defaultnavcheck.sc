if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12247" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "DefaultNav checker" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Net-Square Solutions Pvt Ltd." );
	script_family( "Web application abuses" );
	script_xref( name: "URL", value: "http://www.nextgenss.com/advisories/defaultnav.txt" );
	script_tag( name: "summary", value: "This plugin checks for DefaultNav vulnerabilities on the remote web server

  See the references for more information." );
	script_tag( name: "solution", value: "Disable the DefaultNav functionality within the web server configuration" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

