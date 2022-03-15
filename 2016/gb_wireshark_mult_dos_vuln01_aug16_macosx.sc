CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808286" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-6512", "CVE-2016-6513" );
	script_bugtraq_id( 92174, 92172 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-09 11:43:17 +0530 (Tue, 09 Aug 2016)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities-01 August16 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The 'epan/dissectors/packet-wap.c' script omits an overflow check in the
    'tvb_get_guintvar' function.

  - The 'epan/dissectors/packet-wbxml.c' script does not restrict the recursion
    depth." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 2.0.x before 2.0.5
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.0.5 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2016/07/28/3" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-48.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-49.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: wirversion, test_version: "2.0.0", test_version2: "2.0.4" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.0.5" );
	security_message( data: report );
	exit( 0 );
}

