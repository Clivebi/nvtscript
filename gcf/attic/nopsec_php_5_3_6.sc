if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110013" );
	script_version( "2020-08-17T06:59:22+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 06:59:22 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-14 13:15:22 +0200 (Thu, 14 Jun 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_cve_id( "CVE-2011-0421", "CVE-2011-0708", "CVE-2011-1092", "CVE-2011-1153", "CVE-2011-1464", "CVE-2011-1466", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470" );
	script_bugtraq_id( 46354, 46365, 46786, 46854 );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP Version 5.3 < 5.3.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Upgrade PHP to 5.3.6 or later versions." );
	script_tag( name: "summary", value: "PHP version < 5.3.6 suffers multiple vulnerabilities such as integer overflow vulnerability,
  buffer overflow error and several casting errors." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

