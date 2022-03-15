CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811947" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_cve_id( "CVE-2017-15191" );
	script_bugtraq_id( 101227 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-01 18:12:00 +0000 (Fri, 01 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-10-12 13:42:58 +0530 (Thu, 12 Oct 2017)" );
	script_name( "Wireshark Security Updates (wnpa-sec-2017-44)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the DMP dissector
  which could crash on processing malformed packet." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to make Wireshark crash by injecting
  a malformed packet onto the wire or by convincing someone to read a malformed
  packet trace file." );
	script_tag( name: "affected", value: "Wireshark version 2.4.0 to 2.4.1, 2.2.0
  to 2.2.9, 2.0.0 to 2.0.15 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.4.2, 2.2.10,
  2.0.16." );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-44" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( wirversion, "^(2\\.(0|2|4))" )){
	if( version_in_range( version: wirversion, test_version: "2.4.0", test_version2: "2.4.1" ) ){
		fix = "2.4.2";
	}
	else {
		if( version_in_range( version: wirversion, test_version: "2.2.0", test_version2: "2.2.9" ) ){
			fix = "2.2.10";
		}
		else {
			if(version_in_range( version: wirversion, test_version: "2.0.0", test_version2: "2.0.15" )){
				fix = "2.0.16";
			}
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

