if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800502" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5430" );
	script_bugtraq_id( 32869 );
	script_name( "Thunderbird DoS attacks via malformed MIME emails (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_thunderbird_detect_lin.sc" );
	script_mandatory_keys( "Thunderbird/Linux/Ver" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/364761.php" );
	script_xref( name: "URL", value: "http://www.mozilla.com/en-US/products/thunderbird/" );
	script_tag( name: "impact", value: "Successful exploitation could result in disruption or unavailability
  of service." );
	script_tag( name: "affected", value: "Thunderbird version 2.0.0.14 and prior on Linux." );
	script_tag( name: "solution", value: "Upgrade to Thunderbird version 3.0.4 or later" );
	script_tag( name: "summary", value: "The host is running Mozilla Thunderbird which is prone to a denial
  of service vulnerability." );
	script_tag( name: "insight", value: "Flaw is due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and e-mail messages with many Content-type: message/rfc822 headers." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
tbVer = get_kb_item( "Thunderbird/Linux/Ver" );
if(!tbVer){
	exit( 0 );
}
if(version_is_less_equal( version: tbVer, test_version: "2.0.0.14" )){
	report = report_fixed_ver( installed_version: tbVer, vulnerable_range: "Less than or equal to 2.0.0.14" );
	security_message( port: 0, data: report );
}

