if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805391" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2015-05-28 13:19:38 +0530 (Thu, 28 May 2015)" );
	script_tag( name: "qod", value: "50" );
	script_name( "Synology DiskStation Manager XSS Vulnerability" );
	script_tag( name: "summary", value: "Synology DiskStation Manager is prone to a cross-site scripting
  (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The error exists as input passed via,
  'compound' parameter to the 'entry.cgi' script is not validated before
  returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "Synology DiskStation Manager 5.2-5565" );
	script_tag( name: "solution", value: "Update to the Synology DiskStation Manager
  5.2-5565 Update 1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/132050/synologydiskstation-xss.txt" );
	script_xref( name: "URL", value: "https://www.securify.nl/advisory/SFY20150503/reflected_cross_site_scripting_in_synology_diskstation_manager.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "deprecated", value: TRUE );
	script_xref( name: "URL", value: "https://www.synology.com/en-global/releaseNote/DS214play" );
	exit( 0 );
}
exit( 66 );

