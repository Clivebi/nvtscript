CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807068" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2016-1949" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-02-15 12:34:52 +0530 (Mon, 15 Feb 2016)" );
	script_name( "Mozilla Firefox Security Bypass Vulnerability - Feb16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to same-origin policy bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper restriction of
  the interaction between Service Workers and plugins." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to bypass the Same Origin Policy via a crafted web site that
  triggers spoofed responses to requests that use NPAPI." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 44.0.2 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 44.0.2
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-13" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "44.0.2" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "44.0.2" );
	security_message( data: report );
	exit( 0 );
}

