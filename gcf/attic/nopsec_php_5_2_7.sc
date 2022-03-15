if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110172" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-2371", "CVE-2008-2665", "CVE-2008-2666", "CVE-2008-2829", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658" );
	script_bugtraq_id( 29796, 29797, 29829, 30087, 30649, 31612, 32383, 32625, 32688, 32948 );
	script_name( "PHP Version < 5.2.7 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Update PHP to version 5.2.7 or later." );
	script_tag( name: "summary", value: "PHP version smaller than 5.2.7 suffers from multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

