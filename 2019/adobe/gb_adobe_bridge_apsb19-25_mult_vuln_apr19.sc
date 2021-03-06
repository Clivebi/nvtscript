CPE = "cpe:/a:adobe:bridge_cc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814795" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_cve_id( "CVE-2019-7130", "CVE-2019-7132", "CVE-2019-7133", "CVE-2019-7134", "CVE-2019-7135", "CVE-2019-7138", "CVE-2019-7136", "CVE-2019-7137" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-11 13:48:50 +0530 (Thu, 11 Apr 2019)" );
	script_name( "Adobe Bridge CC Security Updates (apsb19-25)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Adobe Bridge
  CC and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A heap-overflow error.

  - An out-of-bounds write error.

  - A use after free error.

  - A memory corruption error.

  - Multiple out-of-bounds read error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code or gain access to potentially sensitive
  information." );
	script_tag( name: "affected", value: "Adobe Bridge CC before version 9.0.3" );
	script_tag( name: "solution", value: "Upgrade to Adobe Bridge CC 9.0.3 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/bridge/apsb19-25.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_bridge_cc_detect.sc" );
	script_mandatory_keys( "Adobe/Bridge/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "9.0.3.279" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.0.3 (9.0.3.279)", install_path: path );
	security_message( data: report );
	exit( 0 );
}

