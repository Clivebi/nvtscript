CPE = "cpe:/a:magentocommerce:magento";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805372" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-1397", "CVE-2015-1398", "CVE-2015-1399", "CVE-2015-3457", "CVE-2015-3458" );
	script_bugtraq_id( 74298, 74420, 74412 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-04-29 17:25:37 +0530 (Wed, 29 Apr 2015)" );
	script_name( "Magento Web E-Commerce Platform Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with Magento Web
  E-Commerce Platform and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The admin session are not properly validated, It fails to detect controller
    injection technique.

  - The admin templates filters are not properly validated before being returned
    to the user.

  - The 'from' and 'to' keys are not properly validated before being returned
    to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Magento version 1.9.1.0 CE." );
	script_tag( name: "solution", value: "Apply the patch manually." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://blog.checkpoint.com/2015/04/20/analyzing-magento-vulnerability/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_magento_detect.sc" );
	script_mandatory_keys( "magento/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!magVer = get_app_version( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(version_is_equal( version: magVer, test_version: "1.9.1.0" )){
	report = "Installed version: " + magVer + "\n" + "Fixed version:   Apply appropriate Patch  " + "\n";
	security_message( data: report, port: http_port );
	exit( 0 );
}

