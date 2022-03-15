CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807576" );
	script_version( "$Revision: 12313 $" );
	script_cve_id( "CVE-2016-4085" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-05-03 11:09:01 +0530 (Tue, 03 May 2016)" );
	script_name( "Wireshark NCP dissector Denial of Service Vulnerability May16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to stack-based buffer
  overflow in 'epan/dissectors/packet-ncp2222.inc' script in the
  'NCP dissector'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack or possibly have unspecified
  other impact." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.11
  on Windows" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.12.11 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-28.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.10" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "1.12.11" );
	security_message( data: report );
	exit( 0 );
}
