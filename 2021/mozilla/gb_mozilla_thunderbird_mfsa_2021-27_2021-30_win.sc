CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818178" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_cve_id( "CVE-2021-29969", "CVE-2021-29970", "CVE-2021-30547", "CVE-2021-29976" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-19 13:15:00 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-28 23:46:34 +0530 (Wed, 28 Jul 2021)" );
	script_name( "Mozilla Thunderbird Security Updates(mfsa_2021-27_2021-30)-Windows" );
	script_tag( name: "summary", value: "This host is missing a security update
  according to Mozilla." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - IMAP server responses sent by a MITM prior to STARTTLS could be processed.

  - Use-after-free in accessibility features of a document.

  - Out of bounds write in ANGLE.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions and cause a
  denial of service on affected system" );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 78.12 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 78.12
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-30/" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "78.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "78.12", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

