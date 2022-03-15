CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900915" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2853", "CVE-2009-2854" );
	script_bugtraq_id( 35935 );
	script_name( "WordPress 'wp-admin' Multiple Vulnerabilities - Aug09" );
	script_xref( name: "URL", value: "http://core.trac.wordpress.org/changeset/11768" );
	script_xref( name: "URL", value: "http://core.trac.wordpress.org/changeset/11769" );
	script_xref( name: "URL", value: "http://wordpress.org/development/2009/08/wordpress-2-8-3-security-release/" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Attackers can exploit this issue by sending malicious request to several
  scripts in the wp-admin directory to gain access to administrative functions
  which may allow them to obtain sensitive information or elevate privileges." );
	script_tag( name: "affected", value: "WordPress version prior to 2.8.3." );
	script_tag( name: "insight", value: "- Application fails to properly sanitize user supplied input via a direct
  request to admin-footer.php, edit-category-form.php, edit-form-advanced.php,
  edit-form-comment.php, edit-link-category-form.php, edit-link-form.php,
  edit-page-form.php, and edit-tag-form.php in wp-admin/.

  - Application fails to check capabilities for certain actions, it can be
  exploited to cause unauthorized edits or additions via a direct request to
  edit-comments.php, edit-pages.php, import.php, edit-category-form.php,
  edit-link-category-form.php, edit-tag-form.php, export.php, link-add.php
  or edit.php in wp-admin/." );
	script_tag( name: "solution", value: "Update to Version 2.8.3 or later." );
	script_tag( name: "summary", value: "The host is running WordPress and is prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!wpVer = get_app_version( cpe: CPE, port: wpPort )){
	exit( 0 );
}
if(version_is_less( version: wpVer, test_version: "2.8.3" )){
	report = report_fixed_ver( installed_version: wpVer, fixed_version: "2.8.3" );
	security_message( port: wpPort, data: report );
	exit( 0 );
}
exit( 99 );

