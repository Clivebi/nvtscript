if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110186" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2007-3378", "CVE-2007-3997", "CVE-2007-3799", "CVE-2007-4657", "CVE-2007-4658", "CVE-2008-0145", "CVE-2008-2108" );
	script_bugtraq_id( 24661, 49631 );
	script_name( "PHP Version < 4.4.8 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Update PHP to version 4.4.8 or later." );
	script_tag( name: "summary", value: "PHP version smaller than 4.4.8 suffers from multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

