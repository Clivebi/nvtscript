CPE = "cpe:/a:microsoft:edge_chromium_based";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818020" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-21190", "CVE-2021-21189", "CVE-2021-21188", "CVE-2021-21187", "CVE-2021-21186", "CVE-2021-21185", "CVE-2021-21183", "CVE-2021-21182", "CVE-2021-21181", "CVE-2021-21180", "CVE-2021-21179", "CVE-2021-21178", "CVE-2021-21177", "CVE-2021-21176", "CVE-2021-21175", "CVE-2021-21174", "CVE-2021-21173", "CVE-2021-21172", "CVE-2021-21171", "CVE-2021-21170", "CVE-2021-21169", "CVE-2021-21168", "CVE-2021-21167", "CVE-2021-21166", "CVE-2021-21165", "CVE-2021-21164", "CVE-2021-21163", "CVE-2021-21162", "CVE-2021-21161", "CVE-2021-21160", "CVE-2021-21159", "CVE-2020-27844", "CVE-2021-21184", "CVE-2021-21157", "CVE-2021-21156", "CVE-2021-21155", "CVE-2021-21154", "CVE-2021-21153", "CVE-2021-21152", "CVE-2021-21151", "CVE-2021-21150", "CVE-2021-21149" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-03-15 14:29:32 +0530 (Mon, 15 Mar 2021)" );
	script_name( "Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - Mar21" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An Insufficient policy enforcement.

  - An error in Object lifecycle.

  - An Inappropriate implementation in performance APIs.

  - An Stack overflow in GPU Process.
  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges and disclose sensitive information." );
	script_tag( name: "affected", value: "Microsoft Edge (Chromium-Based) prior to version 89.0.774.45." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security" );
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
edgeVer = infos["version"];
path = infos["location"];
if(version_is_less( version: edgeVer, test_version: "89.0.774.45" )){
	report = report_fixed_ver( installed_version: edgeVer, fixed_version: "89.0.774.45", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

