CPE = "cpe:/a:mozilla:seamonkey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805223" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1594", "CVE-2014-1593", "CVE-2014-1592", "CVE-2014-1590", "CVE-2014-1589", "CVE-2014-1588", "CVE-2014-1587", "CVE-2014-8632", "CVE-2014-8631", "CVE-2014-1591" );
	script_bugtraq_id( 71396, 71395, 71398, 71397, 71393, 71392, 71391, 71556, 71560, 71399 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-16 11:56:05 +0530 (Tue, 16 Dec 2014)" );
	script_name( "SeaMonkey Multiple Vulnerabilities-01 Dec14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with SeaMonkey and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A bad cast issue from the BasicThebesLayer to BasicContainerLayer.

  - An error when parsing media content within the 'mozilla::FileBlockCache::Read'
  function.

  - A use-after-free error when parsing certain HTML within the
  'nsHtml5TreeOperation' class.

  - An error that is triggered when handling JavaScript objects that are passed
  to XMLHttpRequest that mimics an input stream.

  - An error that is triggered when handling a CSS stylesheet that has its namespace
  improperly declared.

  - Multiple unspecified errors.

  - An error when filtering object properties via XrayWrappers.

  - An error when passing Chrome Object Wrappers (COW) protected chrome objects as
  native interfaces.

  - An error when handling Content Security Policy (CSP) violation reports
  triggered by a redirect." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose potentially sensitive information, compromise a user's system, bypass
  certain security restrictions and other unknown impacts." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.31 on Windows." );
	script_tag( name: "solution", value: "Upgrade to SeaMonkey version 2.31 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/60558" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2014-83" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2014-84" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Seamonkey/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!smVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: smVer, test_version: "2.31" )){
	report = report_fixed_ver( installed_version: smVer, fixed_version: "2.31" );
	security_message( port: 0, data: report );
	exit( 0 );
}

