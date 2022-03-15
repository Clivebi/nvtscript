CPE = "cpe:/a:oxid:eshop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900935" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3113" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OXID eShop Community Edition Unauthorized Write Access Vulnerability" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/385007.php" );
	script_xref( name: "URL", value: "http://www.oxidforge.org/wiki/Security_bulletins/2009-002" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_oxid_eshop_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oxid_eshop/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain unauthorized
  write access to product reviews via specially crafted URLs." );
	script_tag( name: "affected", value: "OXID eShop Community Edition version 4.x through 4.1.1" );
	script_tag( name: "insight", value: "User supplied data passed to and unspecified variable is not sanitised
  before processing." );
	script_tag( name: "solution", value: "Upgrade to version 4.1.2 or later." );
	script_tag( name: "summary", value: "This host is installed with OXID eShop Community Edition
  and is prone to unauthorized access vulnerability." );
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
if(version_in_range( version: version, test_version: "4.0", test_version2: "4.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

