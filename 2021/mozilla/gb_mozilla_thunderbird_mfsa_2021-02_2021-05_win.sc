CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817896" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-23953", "CVE-2021-23954", "CVE-2020-15685", "CVE-2020-26976", "CVE-2021-23960", "CVE-2021-23964" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-03 20:58:00 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-01-27 11:40:58 +0530 (Wed, 27 Jan 2021)" );
	script_name( "Mozilla Thunderbird Security Updates(mfsa_2021-02_2021-05)-Windows" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Cross-origin information leakage via redirected PDF requests.

  - Type confusion when using logical assignment operators in JavaScript switch
    statements.

  - IMAP Response Injection when using STARTTLS.

  - HTTPS pages could have been intercepted by a registered service worker when
    they should not have been.

  - Use-after-poison for incorrectly redeclared JavaScript variables during GC.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service and disclose
  sensitive information." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before
  78.7 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 78.7
  or later, Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-05/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
tbVer = infos["version"];
tbPath = infos["location"];
if(version_is_less( version: tbVer, test_version: "78.7" )){
	report = report_fixed_ver( installed_version: tbVer, fixed_version: "78.7", install_path: tbPath );
	security_message( data: report );
	exit( 0 );
}

