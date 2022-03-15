if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110180" );
	script_version( "2021-01-18T11:10:48+0000" );
	script_tag( name: "last_modification", value: "2021-01-18 11:10:48 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5814", "CVE-2008-5844" );
	script_bugtraq_id( 32673 );
	script_name( "PHP Version < 5.2.8 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Update PHP to version 5.2.8 or later." );
	script_tag( name: "summary", value: "PHP version smaller than 5.2.8 suffers from multiple vulnerabilities.

  This VT has been replaced by the following VTs:

  - PHP display_errors Cross-Site Scripting Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.800334)

  - PHP FILTER_UNSAFE_RAW SQL Injection Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.800333)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

