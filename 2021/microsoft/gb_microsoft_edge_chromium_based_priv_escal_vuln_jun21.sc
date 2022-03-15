CPE = "cpe:/a:microsoft:edge_chromium_based";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818321" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-33741" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 16:58:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 10:10:36 +0530 (Thu, 10 Jun 2021)" );
	script_name( "Microsoft Edge (Chromium-Based) Elevation of Privilege Vulnerability - June21" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error in Microsoft Edge (Chromium-Based)" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain elevated privileges on affected system." );
	script_tag( name: "affected", value: "Microsoft Edge (Chromium-Based) prior to version 91.0.864.41." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security" );
	script_xref( name: "URL", value: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33741" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "91.0.864.41" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "89.0.4389.114", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

