if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110175" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2006-6383", "CVE-2007-0905", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1383", "CVE-2007-1452", "CVE-2007-1453", "CVE-2007-1454", "CVE-2007-1700", "CVE-2007-1701", "CVE-2007-1824", "CVE-2007-1825", "CVE-2007-1835", "CVE-2007-1884", "CVE-2007-1885", "CVE-2007-1886", "CVE-2007-1887", "CVE-2007-1889", "CVE-2007-1890", "CVE-2007-4441", "CVE-2007-4586" );
	script_bugtraq_id( 21508, 22496, 22805, 22806, 22862, 22922, 23119, 23120, 23219, 23233, 23234, 23235, 23236, 23237, 23238 );
	script_name( "PHP Version < 5.2.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Update PHP to version 5.2.1 or later." );
	script_tag( name: "summary", value: "PHP version smaller than 5.2.1 suffers from multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

