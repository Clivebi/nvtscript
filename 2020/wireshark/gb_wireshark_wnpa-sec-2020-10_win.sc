if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113745" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-17 11:21:47 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-17498" );
	script_name( "Wireshark Security Update (wnpa-sec-2020-10) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "summary", value: "Wireshark is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because of
  a double free during LZ4 decompression in epan/dissectors/packet-kafka.c." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to crash the application." );
	script_tag( name: "affected", value: "Wireshark version 3.2.0 through 3.2.5." );
	script_tag( name: "solution", value: "Update to version 3.2.6." );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2020-10.html" );
	script_xref( name: "URL", value: "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=76afda963de4f0b9be24f2d8e873990a5cbf221b" );
	exit( 0 );
}
CPE = "cpe:/a:wireshark:wireshark";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.6", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

