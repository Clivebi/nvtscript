CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800124" );
	script_version( "$Revision: 14010 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4769" );
	script_bugtraq_id( 28845 );
	script_name( "WordPress cat Parameter Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/29949" );
	script_xref( name: "URL", value: "http://www.juniper.fi/security/auto/vulnerabilities/vuln28845.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary PHP code and
  can even access sensitive information." );
	script_tag( name: "affected", value: "WordPress 2.3.3 and earlier." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of input passed via cat parameter
  to index.php which is not properly sanitized in the get_category_template() function." );
	script_tag( name: "solution", value: "Update to Version 2.5.1 or later." );
	script_tag( name: "summary", value: "The host is installed with WordPress and is prone to Directory Traversal
  Vulnerability." );
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
if(version_is_less_equal( version: ver, test_version: "2.3.3" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.5.1" );
	security_message( port: port, data: report );
}
exit( 99 );

