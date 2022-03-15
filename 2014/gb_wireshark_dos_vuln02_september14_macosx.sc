CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804914" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-6426", "CVE-2014-6425" );
	script_bugtraq_id( 69866, 69863 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-24 15:46:59 +0530 (Wed, 24 Sep 2014)" );
	script_name( "Wireshark DOS Vulnerability-02 Sep14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to:

  - Error in the get_quoted_string and get_unquoted_string functions
    in epan/dissectors/packet-cups.c in the CUPS dissector.

  - The dissect_hip_tlv function in epan/dissectors/packet-hip.c
    in the HIP dissector does not properly handle a NULL tree." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attacker to cause denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.1 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.12.1 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-15.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-16.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "1.12.0" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Equal to 1.12.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

