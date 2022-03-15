if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110068" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_cve_id( "CVE-2007-4850", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2009-0754" );
	script_bugtraq_id( 27413, 30649, 31612, 33542 );
	script_name( "PHP Version < 4.4.9 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Upgrade to PHP version 4.4.9 or later." );
	script_tag( name: "summary", value: "PHP < 4.4.9 suffers from multiple vulnerabilities such as buffer overflow and DOS attack." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

