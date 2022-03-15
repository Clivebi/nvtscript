CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814131" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_cve_id( "CVE-2018-18227" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-10-15 12:06:29 +0530 (Mon, 15 Oct 2018)" );
	script_name( "Wireshark MS-WSP Dissector Denial of Service Vulnerability(wnpa-sec-2018-47)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient validation
  of user-supplied input processed by Microsoft Windows Search Protocol (MS-WSP)
  dissector component." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause a denial of service (DoS) condition on a targeted system." );
	script_tag( name: "affected", value: "Wireshark version 2.6.0 to 2.6.3, 2.4.0 to 2.4.9 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 2.6.4, 2.4.10 or later. Please see the references for more information." );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-47.html" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/viewAlert.x?alertId=59010" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
wirversion = infos["version"];
path = infos["location"];
if( version_in_range( version: wirversion, test_version: "2.6.0", test_version2: "2.6.3" ) ){
	fix = "2.6.4";
}
else {
	if(version_in_range( version: wirversion, test_version: "2.4.0", test_version2: "2.4.9" )){
		fix = "2.4.10";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

