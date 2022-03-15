CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800075" );
	script_version( "$Revision: 12623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2008-12-04 14:15:00 +0100 (Thu, 04 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5285" );
	script_bugtraq_id( 32422 );
	script_name( "Wireshark SMTP Processing Denial of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_lin.sc" );
	script_mandatory_keys( "Wireshark/Linux/Ver" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2008/3231" );
	script_tag( name: "impact", value: "Successful attacks may cause the application to crash via specially
  crafted packets." );
	script_tag( name: "affected", value: "Wireshark versions 1.0.4 and prior on Linux" );
	script_tag( name: "insight", value: "The flaw is due to an error in the SMTP dissector while processing
  large SMTP packets." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.5." );
	script_tag( name: "summary", value: "The Remote host is installed with Wireshark and is prone to
  denial of service vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: ver, test_version: "1.0.4" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "1.0.5" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

