CPE = "cpe:/a:magentocommerce:magento";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807532" );
	script_version( "$Revision: 12149 $" );
	script_cve_id( "CVE-2016-2212" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-04-06 16:24:55 +0530 (Wed, 06 Apr 2016)" );
	script_name( "Magento RSS Feed Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Magento Web
  E-Commerce Platform and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unsafe way of
  comparing 'increment_id' and 'customer_id' parameters in the
  'getOrderByStatusUrlKey' method of the 'Mage_Rss_Helper_Order' class in
  the '/app/code/core/Mage/Rss/Helper/Order.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to download order comments and other order-related information." );
	script_tag( name: "affected", value: "Magento CE 1.9.2.2 and prior versions." );
	script_tag( name: "solution", value: "Update to Magento CE 1.9.2.3 or later or
  apply the SUPEE-7405 patch bundle available at the references." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/135941/KIS-2016-02.txt" );
	script_xref( name: "URL", value: "https://magento.com/security/patches/supee-7405" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_magento_detect.sc" );
	script_mandatory_keys( "magento/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.magentocommerce.com/products/downloads/magento" );
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
if(version_is_less_equal( version: magVer, test_version: "1.9.2.2" )){
	report = report_fixed_ver( installed_version: magVer, fixed_version: "1.9.2.3" );
	security_message( data: report, port: http_port );
	exit( 0 );
}
exit( 99 );

