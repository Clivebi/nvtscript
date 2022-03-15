CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808289" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-6507", "CVE-2016-6504" );
	script_bugtraq_id( 92167, 92164 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:33:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2016-08-09 10:31:32 +0530 (Tue, 09 Aug 2016)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities-03 August16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'epan/dissectors/packet-mmse.c' script could cause the
    MMSE dissector to go into a long loop.

  - The 'epan/dissectors/packet-ncp2222.inc' script in the NDS dissector
    does not properly maintain a ptvc data structure." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.13
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.12.13
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2016/07/28/3" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-43.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-40.html" );
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
if(version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.12" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "1.12.13" );
	security_message( data: report );
	exit( 0 );
}

