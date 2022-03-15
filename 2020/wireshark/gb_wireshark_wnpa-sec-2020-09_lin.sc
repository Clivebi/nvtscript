CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817216" );
	script_version( "2021-10-04T14:22:38+0000" );
	script_cve_id( "CVE-2020-15466" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-10 20:16:00 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-07-09 12:53:40 +0530 (Thu, 09 Jul 2020)" );
	script_name( "Wireshark Security Update (wnpa-sec-2020-09) - Linux" );
	script_tag( name: "summary", value: "Wireshark is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to GVCP dissector
  could go into an infinite loop." );
	script_tag( name: "impact", value: "Successful exploitation may allow
  remote attackers perform denial of service." );
	script_tag( name: "affected", value: "Wireshark versions 3.2.0 to 3.2.4." );
	script_tag( name: "solution", value: "Update to version 3.2.5 or later." );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2020-09" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_lin.sc" );
	script_mandatory_keys( "Wireshark/Linux/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.2.5", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

