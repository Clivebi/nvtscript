CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100505" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-02-24 18:35:31 +0100 (Wed, 24 Feb 2010)" );
	script_bugtraq_id( 38368 );
	script_cve_id( "CVE-2010-0682" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "WordPress Trashed Posts Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38368" );
	script_xref( name: "URL", value: "http://tmacuk.co.uk/?p=180" );
	script_xref( name: "URL", value: "http://wordpress.org/development/2010/02/wordpress-2-9-2/" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "WordPress is prone to an information-disclosure vulnerability because
  it fails to properly restrict access to trashed posts." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view other authors'
  trashed posts, which may aid in further attacks." );
	script_tag( name: "affected", value: "Versions prior to WordPress 2.9.2 are vulnerable." );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "2.9.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.9.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

