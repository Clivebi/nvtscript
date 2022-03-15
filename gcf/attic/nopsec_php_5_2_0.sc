if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110173" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2006-1015", "CVE-2006-1549", "CVE-2006-2660", "CVE-2006-4486", "CVE-2006-4625", "CVE-2006-4812", "CVE-2006-5465", "CVE-2006-5706", "CVE-2006-7205", "CVE-2007-0448", "CVE-2007-1381", "CVE-2007-1584", "CVE-2007-1888", "CVE-2007-2844", "CVE-2007-5424" );
	script_bugtraq_id( 20349, 20879, 49634 );
	script_name( "PHP Version < 5.2.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Update PHP to version 5.2.0 or later." );
	script_tag( name: "summary", value: "PHP version smaller than 5.2.0 suffers from multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

