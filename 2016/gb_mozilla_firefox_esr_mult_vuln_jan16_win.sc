CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807050" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-1935", "CVE-2016-1930" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-01-29 10:46:42 +0530 (Fri, 29 Jan 2016)" );
	script_name( "Mozilla Firefox ESR Multiple Vulnerabilities - Jan16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox ESR and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A buffer-overflow vulnerability.

  - A memory-corruption vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow for
  arbitrary code execution in the context of the logged on user or vulnerable
  application, crash the affected application." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 38.x
  before 38.6 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version
  38.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://msisac.cisecurity.org/advisories/2016/2016-018.cfm" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-01" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( ffVer, "^38" )){
	if(version_is_less( version: ffVer, test_version: "38.6" )){
		report = report_fixed_ver( installed_version: ffVer, fixed_version: "38.6" );
		security_message( data: report );
		exit( 0 );
	}
}

