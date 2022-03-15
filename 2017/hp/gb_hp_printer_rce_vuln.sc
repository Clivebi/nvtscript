if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113056" );
	script_version( "2021-09-13T12:36:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:36:48 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-23 10:11:12 +0100 (Thu, 23 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-21 15:57:00 +0000 (Wed, 21 Feb 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-2750" );
	script_name( "HP Printers RCE Vulnerability (CVE-2017-2750)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_hp_printer_detect.sc" );
	script_mandatory_keys( "hp_printer/installed" );
	script_tag( name: "summary", value: "Multiple HP Printers are vulnerable to remote code execution
  (RCE) attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A flaw in HP's Digital Signature Validation makes it possible to
  load malicious DLLs onto an HP printer and use it to execute arbitrary code on the machine." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute
  arbitrary code on the target machine." );
	script_tag( name: "affected", value: "Please see the linked vendor advisory for a full list of
  affected devices and firmware versions." );
	script_tag( name: "solution", value: "Update to the fixed firmware version." );
	script_xref( name: "URL", value: "https://foxglovesecurity.com/2017/11/20/a-sheep-in-wolfs-clothing-finding-rce-in-hps-printer-fleet/#arbcode" );
	script_xref( name: "URL", value: "https://support.hp.com/nz-en/document/c05839270" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "hp_model" )){
	exit( 0 );
}
if(!version = get_kb_item( "hp_fw_ver" )){
	exit( 0 );
}
forty_one = make_list( "LaserJet[A-Za-z ]*Flow MFP M631",
	 "LaserJet[A-Za-z ]*Flow MFP M632",
	 "LaserJet[A-Za-z ]*Flow MFP M633",
	 "LaserJet[A-Za-z ]*MFP M631",
	 "LaserJet[A-Za-z ]*MFP M632",
	 "LaserJet[A-Za-z ]*MFP M633",
	 "LaserJet[A-Za-z ]*Flow MFP E62555",
	 "LaserJet[A-Za-z ]*Flow MFP E62565",
	 "LaserJet[A-Za-z ]*Flow MFP E62575",
	 "LaserJet[A-Za-z ]*MFP E62555",
	 "LaserJet[A-Za-z ]*MFP E62565" );
forty_seven = make_list( "Color LaserJet[A-Za-z ]*M651" );
sixty_eight = make_list( "Color LaserJet[A-Za-z ]*M652",
	 "Color LaserJet[A-Za-z ]*M563",
	 "Color LaserJet[A-Za-z ]*E65050",
	 "Color LaserJet[A-Za-z ]*E65060" );
thirty_eight = make_list( "Color LaserJet[A-Za-z ]*MFP M577" );
three_fifteen = make_list( "Color LaserJet[A-Za-z ]*M552",
	 "Color LaserJet[A-Za-z ]*M553" );
forty_two = make_list( "Color LaserJet M680" );
forty_five = make_list( "LaserJet[A-Za-z ]*500 color MFP M575",
	 "LaserJet[A-Za-z ]*color flow MFP M575" );
forty_eight = make_list( "LaserJet[A-Za-z ]*500 MFP M525",
	 "LaserJet[A-Za-z ]*flow MFP M525" );
sixty_one = make_list( "LaserJet[A-Za-z ]*700 color MFP M775" );
fifty_seven = make_list( "LaserJet[A-Za-z ]*800 color M855" );
fifty_four = make_list( "LaserJet[A-Za-z ]*800 color MFP M880" );
sixty = make_list( "LaserJet[A-Za-z ]*flow M830z MFP" );
forty = make_list( "LaserJet[A-Za-z ]*MFP M630",
	 "LaserJet[A-Za-z ]*Flow MFP M630" );
thirty_nine = make_list( "LaserJet[A-Za-z ]*M527" );
sixty_nine = make_list( "LaserJet[A-Za-z ]*M607",
	 "LaserJet[A-Za-z ]*M608",
	 "LaserJet[A-Za-z ]*M609",
	 "LaserJet[A-Za-z ]*E60055",
	 "LaserJet[A-Za-z ]*E60065",
	 "LaserJet[A-Za-z ]*E60075" );
fifty_nine = make_list( "LaserJet[A-Za-z ]*M806" );
fifty_eight = make_list( "LaserJet[A-Za-z ]*MFP M725" );
fifty = make_list( "OfficeJet[A-Za-z ]*Color Flow MFP X585",
	 "OfficeJet[A-Za-z ]*Color MFP X585" );
five_sixty_four = make_list( "PageWide[A-Za-z ]*Color 765",
	 "PageWide[A-Za-z ]*Color E75160" );
sixty_six = make_list( "PageWide[A-Za-z ]*Color MFP 586",
	 "PageWide[A-Za-z ]*Color Flow MFP 586" );
five_forty_eight = make_list( "PageWide[A-Za-z ]*Color MPF 780",
	 "PageWide[A-Za-z ]*Color MPF 785",
	 "PageWide[A-Za-z ]*Color Flow MFP E77650",
	 "PageWide[A-Za-z ]*Color Flow MFP E77660",
	 "PageWide[A-Za-z ]*Color MFP E77650" );
fifty_one = make_list( "PageWide[A-Za-z ]*Color X556",
	 "PageWide[A-Za-z ]*Color E55650" );
five_fifty_two = make_list( "ScanJet[A-Za-z ]*Flow N9120 Doc Flatbed Scanner" );
five_fifty_three = make_list( "Digital Sender Flow 8500 fn2 Doc Capture Workstation" );
func check_vuln_firmware( fixed_version ){
	var fixed_version;
	if(fixed_version && version_is_less( version: version, test_version: fixed_version )){
		report = report_fixed_ver( installed_version: version, fixed_version: fixed_version );
		security_message( data: report, port: 0 );
		exit( 0 );
	}
}
for pattern in forty_one {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000041" );
	}
}
for pattern in forty_seven {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000047" );
	}
}
for pattern in sixty_eight {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000068" );
	}
}
for pattern in thirty_eight {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000038" );
	}
}
for pattern in three_fifteen {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2308903_577315" );
	}
}
for pattern in forty_two {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000042" );
	}
}
for pattern in forty_five {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000045" );
	}
}
for pattern in forty_eight {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000048" );
	}
}
for pattern in sixty_one {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000061" );
	}
}
for pattern in fifty_seven {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000057" );
	}
}
for pattern in fifty_four {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000054" );
	}
}
for pattern in sixty {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000060" );
	}
}
for pattern in forty {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_00040" );
	}
}
for pattern in thirty_nine {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000039" );
	}
}
for pattern in sixty_nine {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405130_000069" );
	}
}
for pattern in fifty_nine {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000059" );
	}
}
for pattern in fifty_eight {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000058" );
	}
}
for pattern in fifty {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000050" );
	}
}
for pattern in five_sixty_four {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405087_18564" );
	}
}
for pattern in sixty_six {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000066" );
	}
}
for pattern in five_forty_eight {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405087_018548" );
	}
}
for pattern in fifty_one {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405129_000051" );
	}
}
for pattern in five_fifty_two {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405087_018552" );
	}
}
for pattern in five_fifty_three {
	if(eregmatch( pattern: pattern, string: model, icase: TRUE )){
		check_vuln_firmware( fixed_version: "2405087_018223" );
	}
}
exit( 99 );

