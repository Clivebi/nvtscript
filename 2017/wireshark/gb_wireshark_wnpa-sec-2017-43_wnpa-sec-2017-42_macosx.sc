CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811946" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_cve_id( "CVE-2017-15193", "CVE-2017-15192" );
	script_bugtraq_id( 101240, 101235 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-17 20:01:00 +0000 (Tue, 17 Oct 2017)" );
	script_tag( name: "creation_date", value: "2017-10-12 13:42:13 +0530 (Thu, 12 Oct 2017)" );
	script_name( "Wireshark Security Updates (wnpa-sec-2017-43_wnpa-sec-2017-42)-MACOSX" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The MBIM dissector could crash or exhaust system memory.

  - Attribute Protocol dissector could crash." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to make Wireshark crash or exhaust
  system memory by injecting a malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file. It may be possible to make
  Wireshark crash by injecting a malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file." );
	script_tag( name: "affected", value: "Wireshark version 2.4.0 to 2.4.1, 2.2.0 to 2.2.9 on MACOSX." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.4.2, 2.2.10
  or later." );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-43" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-42" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( wirversion, "^(2\\.(2|4))" )){
	if( version_in_range( version: wirversion, test_version: "2.4.0", test_version2: "2.4.1" ) ){
		fix = "2.4.2";
	}
	else {
		if(version_in_range( version: wirversion, test_version: "2.2.0", test_version2: "2.2.9" )){
			fix = "2.2.10";
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

