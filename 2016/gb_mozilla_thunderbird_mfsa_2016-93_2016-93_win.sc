CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809821" );
	script_version( "2021-09-17T12:01:50+0000" );
	script_cve_id( "CVE-2016-5296", "CVE-2016-5294", "CVE-2016-5297", "CVE-2016-9066", "CVE-2016-5291", "CVE-2016-9074", "CVE-2016-5290" );
	script_bugtraq_id( 94339, 94336, 94341, 94335 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 12:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-30 12:53:00 +0000 (Mon, 30 Jul 2018)" );
	script_tag( name: "creation_date", value: "2016-12-01 11:45:00 +0530 (Thu, 01 Dec 2016)" );
	script_name( "Mozilla Thunderbird Security Update (mfsa_2016-93_2016-93) - Windows" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Heap-buffer-overflow WRITE in rasterize_edges_1.

  - Arbitrary target directory for result files of update process.

  - Incorrect argument length checking in JavaScript.

  - Integer overflow leading to a buffer overflow in nsScriptLoadHandler.

  - Same-origin policy violation using local HTML file and saved shortcut file.

  - Insufficient timing side-channel resistance in divSpoiler." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information, and
  to cause a denial of service." );
	script_tag( name: "affected", value: "Mozilla Thunderbird versions before 45.5." );
	script_tag( name: "solution", value: "Update to version 45.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-93" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "45.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "45.5", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

