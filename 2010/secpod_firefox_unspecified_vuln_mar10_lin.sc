if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902148" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)" );
	script_cve_id( "CVE-2010-1122" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Firefox Unspecified Vulnerability Mar-10 (Linux)" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/392231.php" );
	script_xref( name: "URL", value: "http://www.security-database.com/cvss.php?alert=CVE-2010-1122" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Impact is currently unknown." );
	script_tag( name: "affected", value: "Mozilla Firefox version 3.5.x through 3.5.8 on Linux." );
	script_tag( name: "insight", value: "Vulnerability details are currently not available." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.3 or later" );
	script_tag( name: "summary", value: "The host is installed with mozilla Firefox and is prone to
  unspecified vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
fpVer = get_kb_item( "Firefox/Linux/Ver" );
if(!fpVer){
	exit( 0 );
}
if(version_in_range( version: fpVer, test_version: "3.5.0", test_version2: "3.5.8" )){
	report = report_fixed_ver( installed_version: fpVer, vulnerable_range: "3.5.0 - 3.5.8" );
	security_message( port: 0, data: report );
}

