CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813035" );
	script_version( "2021-07-01T02:00:36+0000" );
	script_cve_id( "CVE-2018-5127", "CVE-2018-5129", "CVE-2018-5130", "CVE-2018-5131", "CVE-2018-5144", "CVE-2018-5125", "CVE-2018-5145" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 14:21:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-03-15 11:21:49 +0530 (Thu, 15 Mar 2018)" );
	script_name( "Mozilla Firefox ESR Security Updates(mfsa_2018-06_2018-07)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A buffer overflow error when manipulating SVG animatedPathSegList through script.

  - A lack of parameter validation on IPC messages.

  - A memory corruption error when packets with a mismatched RTP payload type are
    sent in WebRTC connections.

  - Fetch API improperly returns cached copies of no-store/no-cache resources.

  - An integer overflow error during Unicode conversion.

  - Memory safety bugs fixed." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to crash the affected system, conduct sandbox escape, access sensitive data
  and bypass security restrictions." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 52.7 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 52.7
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-07" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less( version: ffVer, test_version: "52.7" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "52.7", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

