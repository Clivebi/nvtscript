CPE = "cpe:/a:adobe:framemaker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817294" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9726", "CVE-2020-9725" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 02:22:00 +0000 (Fri, 11 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-10 12:06:45 +0530 (Thu, 10 Sep 2020)" );
	script_name( "Adobe Framemaker Security Update (APSB20-54) - Windows" );
	script_tag( name: "summary", value: "Adobe Framemaker is prone to multiple vulnerabilities" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An out-of-bounds read error.

  - Stack-based Buffer Overflow error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the system." );
	script_tag( name: "affected", value: "Adobe Framemaker 2019.0.6 and earlier versions." );
	script_tag( name: "solution", value: "Update to version 2019.0.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/framemaker/apsb20-54.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_framemaker_detect_win.sc" );
	script_mandatory_keys( "AdobeFrameMaker/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "2019.0.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2019.0.7", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

