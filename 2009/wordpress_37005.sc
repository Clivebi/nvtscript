CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100345" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-11-13 18:49:45 +0100 (Fri, 13 Nov 2009)" );
	script_bugtraq_id( 37005 );
	script_cve_id( "CVE-2009-3890" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_name( "WordPress 'wp-admin/includes/file.php' Arbitrary File Upload Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37005" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/507819" );
	script_xref( name: "URL", value: "http://wordpress.org/development/2009/11/wordpress-2-8-6-security-release/" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "WordPress is prone to a vulnerability that lets attackers upload
  arbitrary files. The issue occurs because the application fails to
  adequately sanitize user-supplied input." );
	script_tag( name: "insight", value: "Note that this issue only arises in certain Apache configurations that
  are using the Add* directives and PHP to facilitate handling of files with multiple extensions." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to upload arbitrary code
  and run it in the context of the webserver process. This may facilitate unauthorized access or privilege
  escalation. Other attacks are also possible." );
	script_tag( name: "affected", value: "WordPress 2.8.5 and prior versions are vulnerable." );
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
if(version_is_less( version: vers, test_version: "2.8.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.8.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

