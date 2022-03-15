if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.110012" );
	script_version( "2021-01-18T11:10:48+0000" );
	script_tag( name: "last_modification", value: "2021-01-18 11:10:48 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2012-06-14 13:15:22 +0200 (Thu, 14 Jun 2012)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_cve_id( "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0781", "CVE-2012-0788", "CVE-2012-0789" );
	script_bugtraq_id( 50907, 51193, 51806, 51952, 51992, 52043 );
	script_name( "PHP Version < 5.3.9 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 NopSec Inc." );
	script_tag( name: "solution", value: "Upgrade PHP to 5.3.9 or versions after." );
	script_tag( name: "summary", value: "PHP version < 5.3.9 suffers from multiple vulnerabilities such as DOS by sending crafted requests
  including hash collision parameter values. Several errors exist in some certain functions as well.

  This VT has been replaced by the following VTs:

  - PHP EXIF Header Denial of Service Vulnerability (Windows) (OID: 1.3.6.1.4.1.25623.1.0.802349)

  - PHP Web Form Hash Collision Denial of Service Vulnerability (Windows) (OID: 1.3.6.1.4.1.25623.1.0.802408)

  - PHP Security Bypass Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.103464)

  - PHP Multiple Denial of Service Vulnerabilities (Windows) (OID: 1.3.6.1.4.1.25623.1.0.802566)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

