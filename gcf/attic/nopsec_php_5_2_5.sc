if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110179" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2007-3996", "CVE-2007-4782", "CVE-2007-4783", "CVE-2007-4784", "CVE-2007-4825", "CVE-2007-4840", "CVE-2007-4887", "CVE-2007-4889", "CVE-2007-5447", "CVE-2007-5653", "CVE-2007-5898", "CVE-2007-5899", "CVE-2007-5900", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-4107" );
	script_bugtraq_id( 26403 );
	script_name( "PHP Version < 5.2.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Update PHP to version 5.2.5 or later." );
	script_tag( name: "summary", value: "PHP version smaller than 5.2.5 suffers from multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

