CPE = "cpe:/a:magentocommerce:magento";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106792" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-04-27 10:41:56 +0200 (Thu, 27 Apr 2017)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Magento Arbitrary File Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_magento_detect.sc" );
	script_mandatory_keys( "magento/installed" );
	script_tag( name: "summary", value: "Magento Web E-Commerce Platform is prone to an arbitrary file upload
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A high risk vulnerability was discovered in Magento that could lead to
remote code execution and thus the complete system compromise including the database containing sensitive
customer information such as stored credit card numbers and other payment information. The main attack vector
uses an additional Cross Site Request Forgery vulnerability." );
	script_tag( name: "affected", value: "Magento CE and EE prior to 2.0.14/2.1.7." );
	script_tag( name: "solution", value: "Update to version 2.0.14/2.1.7 or later." );
	script_xref( name: "URL", value: "https://magento.com/security/patches/magento-2014-and-217-security-update" );
	script_xref( name: "URL", value: "http://www.defensecode.com/advisories/DC-2017-04-003_Magento_Arbitrary_File_Upload.pdf" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\.0" )){
	if(version_is_less( version: version, test_version: "2.0.14" )){
		vuln = TRUE;
		fix = "2.0.14";
	}
}
if(IsMatchRegexp( version, "^2\\.1" )){
	if(version_is_less( version: version, test_version: "2.1.7" )){
		vuln = TRUE;
		fix = "2.1.7";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

