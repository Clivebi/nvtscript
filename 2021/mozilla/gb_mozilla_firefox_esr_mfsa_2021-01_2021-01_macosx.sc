CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817566" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2020-16044" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 21:09:00 +0000 (Thu, 11 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-08 10:43:16 +0530 (Fri, 08 Jan 2021)" );
	script_name( "Mozilla Firefox ESR Security Updates(mfsa_2021-01_2021-01)-MAC OS X" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to use-after-free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to:
  Use-after-free write when handling a malicious COOKIE-ECHO SCTP chunk." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to run arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before
  78.6.1 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 78.6.1
  or later, Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-01/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "78.6.1" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "78.6.1", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}

