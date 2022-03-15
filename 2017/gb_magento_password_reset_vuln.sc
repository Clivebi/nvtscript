CPE = "cpe:/a:magentocommerce:magento";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112088" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-10-19 15:32:56 +0200 (Thu, 19 Oct 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Magento Password Reset Process Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_magento_detect.sc" );
	script_mandatory_keys( "magento/installed" );
	script_tag( name: "summary", value: "Magento Web E-Commerce Platform is prone to an insufficient protection of the password reset process." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The token to reset passwords is passed via a GET request and not cancelled after use.
      This means it leaks in the referrer field to all external services called on the page (image servers, analytics, ads) and can be potentially reused to steal customer passwords." );
	script_tag( name: "affected", value: "Magento CE prior to 1.9.2.2 and EE prior to 1.14.2.2." );
	script_tag( name: "solution", value: "Upgrade to Magento CE 1.9.2.2 or later and/or upgrade to Magento EE 1.14.2.2 or later" );
	script_xref( name: "URL", value: "https://magento.com/security/patches/supee-6788" );
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
CE = get_kb_item( "magento/CE/installed" );
EE = get_kb_item( "magento/EE/installed" );
if(CE || IsMatchRegexp( version, "^1\\.9" )){
	if(version_is_less( version: version, test_version: "1.9.2.2" )){
		vuln = TRUE;
		fix = "1.9.2.2";
	}
}
if(EE || IsMatchRegexp( version, "^1\\.14" )){
	if(version_is_less( version: version, test_version: "1.14.2.2" )){
		vuln = TRUE;
		fix = "1.14.2.2";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

