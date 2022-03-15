if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110067" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_cve_id( "CVE-2006-1017", "CVE-2006-4020", "CVE-2006-4481", "CVE-2006-4482", "CVE-2006-4483", "CVE-2006-4484", "CVE-2006-4485" );
	script_bugtraq_id( 16878, 19415, 19582 );
	script_name( "PHP Version 5.1.x < 5.1.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Upgrade to PHP version 5.1.5 or later." );
	script_tag( name: "summary", value: "PHP 5.1.x < 5.1.5 suffers from multiple vulnerabilities such as a buffer overflow,
  user authentication bypass and Multiple heap-based buffer overflows." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

