CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813882" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_cve_id( "CVE-2018-16058", "CVE-2018-16057", "CVE-2018-16056" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-31 15:44:50 +0530 (Fri, 31 Aug 2018)" );
	script_name( "Wireshark Security Updates (wnpa-sec-2018-44_wnpa-sec-2018-46_wnpa-sec-2018-45) MACOSX" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A missing validation for iterator operations in 'epan/dissectors/packet-ieee80211-radiotap-iter.c'
    script.

  - An improper initialization of a data structure in 'epan/dissectors/packet-btavdtp.c'
    script.

  - An improper handling of UUID in 'epan/dissectors/packet-btatt.c' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to crash the affected application or to consume excess memory, denying service
  to legitimate users." );
	script_tag( name: "affected", value: "Wireshark version 2.6.0 to 2.6.2, 2.4.0 to
  2.4.8 and 2.2.0 to 2.2.16 on Macosx." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.6.3, 2.4.9 or
  2.2.17 or later. Please see the references for more information." );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-44" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-46" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-45" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
wirversion = infos["version"];
path = infos["location"];
if( version_in_range( version: wirversion, test_version: "2.6.0", test_version2: "2.6.2" ) ){
	fix = "2.6.3";
}
else {
	if( version_in_range( version: wirversion, test_version: "2.4.0", test_version2: "2.4.8" ) ){
		fix = "2.4.9";
	}
	else {
		if(version_in_range( version: wirversion, test_version: "2.2.0", test_version2: "2.2.16" )){
			fix = "2.2.17";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

