if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143107" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-11-11 05:25:54 +0000 (Mon, 11 Nov 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-25 14:52:00 +0000 (Mon, 25 Nov 2019)" );
	script_cve_id( "CVE-2019-6337", "CVE-2019-10627", "CVE-2019-16240" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP Printers Multiple Vulnerabilities (HPSBPI03630)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hp_printer_detect.sc" );
	script_mandatory_keys( "hp_printer/installed" );
	script_tag( name: "summary", value: "A maliciously crafted print file might cause certain HP Inkjet printers to
  assert. Under certain circumstances, the printer produces a core dump to a local device." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "HP OfficeJet Pro and HP PageWide Printers." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://support.hp.com/us-en/document/c06458150" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "hp_model" )){
	exit( 0 );
}
if(!fw_ver = get_kb_item( "hp_fw_ver" )){
	exit( 0 );
}
if(IsMatchRegexp( model, "^OfficeJet Pro 8210" )){
	if(version_is_less( version: fw_ver, test_version: "TESPDLPP1N001.1937C.00" )){
		report = report_fixed_ver( installed_version: fw_ver, fixed_version: "TESPDLPP1N001.1937C.00" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( model, "^PageWide 352dw" )){
	if(version_is_less( version: fw_ver, test_version: "ICEMDWPP1N001.1937D.00" )){
		report = report_fixed_ver( installed_version: fw_ver, fixed_version: "ICEMDWPP1N001.1937D.00" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( model, "^PageWide 377dw" )){
	if(version_is_less( version: fw_ver, test_version: "MAVEDWPP1N001.1937D.00" )){
		report = report_fixed_ver( installed_version: fw_ver, fixed_version: "MAVEDWPP1N001.1937D.00" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( model, "^PageWide Pro 452dn" )){
	if(version_is_less( version: fw_ver, test_version: "ICEMDNPP1N001.1937D.00" )){
		report = report_fixed_ver( installed_version: fw_ver, fixed_version: "ICEMDNPP1N001.1937D.00" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( model, "^PageWide Pro 477dn" )){
	if(version_is_less( version: fw_ver, test_version: "MAVEDNPP1N001.1937D.00" )){
		report = report_fixed_ver( installed_version: fw_ver, fixed_version: "MAVEDNPP1N001.1937D.00" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( model, "^PageWide Pro 477dw" )){
	if(version_is_less( version: fw_ver, test_version: "MAVEDWPP1N001.1937D.00" )){
		report = report_fixed_ver( installed_version: fw_ver, fixed_version: "MAVEDWPP1N001.1937D.00" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 0 );

