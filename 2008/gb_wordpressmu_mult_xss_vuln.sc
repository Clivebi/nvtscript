CPE = "cpe:/a:wordpress:wordpress_mu";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800125" );
	script_version( "$Revision: 14010 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-4671" );
	script_bugtraq_id( 31482 );
	script_name( "WordPress MU Multiple XSS Vulnerabilities - Oct08" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32060" );
	script_xref( name: "URL", value: "http://www.juniper.fi/security/auto/vulnerabilities/vuln28845.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary HTML and
  script code in the context of an affected site and attackers can steal cookie-based authentication credentials." );
	script_tag( name: "affected", value: "WordPress MU before 2.6 on all running platform." );
	script_tag( name: "insight", value: "The flaws are due to the 's' and 'ip_address' parameters in
  wp-admin/wp-blogs.php which is not properly sanitized before being returned to the user." );
	script_tag( name: "solution", value: "Update to Version 2.6 or later." );
	script_tag( name: "summary", value: "The host is running WordPress MU, which is prone to multiple
  XSS vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "2.6" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

