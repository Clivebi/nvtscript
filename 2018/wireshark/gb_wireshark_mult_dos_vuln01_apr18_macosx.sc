CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813069" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-9257", "CVE-2018-9258" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-04-05 16:18:35 +0530 (Thu, 05 Apr 2018)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities -01 Apr18 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:
  multiple input validation errors in 'epan/dissectors/packet-tcp.c' and
  'epan/dissectors/packet-cql.c' scripts." );
	script_tag( name: "impact", value: "Successful exploitation will make Wireshark
  crash by injecting malformed packets." );
	script_tag( name: "affected", value: "Wireshark version 2.4.0 to 2.4.5 on
  Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.4.6 or later. Please see the references for more information." );
	script_xref( name: "URL", value: "https://www.wireshark.org/#download" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-21" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-22" );
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
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "2.4.0", test_version2: "2.4.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.6", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

