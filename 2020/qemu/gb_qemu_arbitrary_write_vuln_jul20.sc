if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113730" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-22 09:58:28 +0000 (Wed, 22 Jul 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 20:15:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-13765" );
	script_name( "QEMU <= 4.1.0 Arbitrary Write Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_qemu_detect_lin.sc" );
	script_mandatory_keys( "QEMU/Lin/Ver" );
	script_tag( name: "summary", value: "QEMU is prone to an arbitrary write vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "rom_copy() in hw/core/loader.c does not validate the relationship between two addresses,
  which allows attackers to trigger an invalid memory copy operation." );
	script_tag( name: "affected", value: "QEMU through version 4.1.0." );
	script_tag( name: "solution", value: "Update to version 4.1.1 or later." );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00032.html" );
	exit( 0 );
}
CPE = "cpe:/a:qemu:qemu";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "4.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.1", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

