if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143413" );
	script_version( "2021-09-10T12:50:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:50:44 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-01-29 04:32:43 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-13 05:15:00 +0000 (Fri, 13 Sep 2019)" );
	script_cve_id( "CVE-2019-14301", "CVE-2019-14304", "CVE-2019-14305", "CVE-2019-14307" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "RICOH Printers M C250FW, M C250FWB, P C300W, P C301W < 1.02 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ricoh_printer_consolidation.sc" );
	script_mandatory_keys( "ricoh/printer/detected" );
	script_tag( name: "summary", value: "RICOH printers and multifunction printers are prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "RICOH printers and multifunction printers are prone to multiple vulnerabilities:

  - Incorrect Access Control (CVE-2019-14301)

  - CSRF vulnerability (CVE-2019-14304)

  - Multiple buffer overflows parsing HTTP parameter settings for Wi-Fi, mDNS, POP3, SMTP, and notification alerts
    (CVE-2019-14305)

  - Multiple buffer overflows parsing HTTP parameter settings for SNMP (CVE-2019-14307)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "RICOH M C250FW, M C250FWB, P C300W and P C301W before firmware version 1.02." );
	script_tag( name: "solution", value: "Update firmware to version 1.02 or later." );
	script_xref( name: "URL", value: "https://www.ricoh.com/info/2019/0823_1/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_array( "cpe:/o:ricoh:m_c250fw_firmware", "1.02", "cpe:/o:ricoh:m_c250fwb_firmware", "1.02", "cpe:/o:ricoh:p_c300w_firmware", "1.02", "cpe:/o:ricoh:p_c301w_firmware", "1.02" );
test_list = make_list();
for cpe in keys( cpe_list ) {
	test_list = make_list( test_list,
		 cpe );
}
if(!infos = get_app_version_from_list( cpe_list: test_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
fix = cpe_list[cpe];
if(!fix){
	exit( 0 );
}
version = infos["version"];
if(version_is_less( version: version, test_version: fix )){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

