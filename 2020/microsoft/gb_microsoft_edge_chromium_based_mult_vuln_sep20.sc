CPE = "cpe:/a:microsoft:edge_chromium_based";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817380" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-16884" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 14:10:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)" );
	script_name( "Microsoft Edge (Chromium-Based) Memory Corruption Vulnerability - Sep20" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the way that
  the IEToEdge Browser Helper Object (BHO) plugin on Internet Explorer handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  execute arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Edge (Chromium-Based) prior to version 85.0.564.51." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-16884" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_microsoft_edge_chromium_based_detect_win.sc" );
	script_mandatory_keys( "microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
edgeVer = infos["version"];
path = infos["location"];
if(version_is_less( version: edgeVer, test_version: "85.0.564.51" )){
	report = report_fixed_ver( installed_version: edgeVer, fixed_version: "85.0.564.51", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

