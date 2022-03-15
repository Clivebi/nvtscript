CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800375" );
	script_version( "$Revision: 12629 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-6472" );
	script_name( "Wireshark Denial of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_lin.sc" );
	script_mandatory_keys( "Wireshark/Linux/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32840" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2008-07.html" );
	script_tag( name: "impact", value: "Successful attacks may cause the application to crash via unspecified
  attack vectors." );
	script_tag( name: "affected", value: "Wireshark version prior to 1.0.5 on Linux." );
	script_tag( name: "insight", value: "Error in the WLCCP and SMTP dissector allows to exploit by triggering the
  execution into an infinite loop through specially crafted packets." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.5." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial
  of service vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "1.0.5" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "1.0.5" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

