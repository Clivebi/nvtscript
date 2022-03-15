if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.90013" );
	script_version( "2020-04-14T08:15:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-14 08:15:28 +0000 (Tue, 14 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2007-4879", "CVE-2008-1195", "CVE-2008-1240", "CVE-2008-1241" );
	script_bugtraq_id( 28448 );
	script_name( "Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-2.0/#firefox2.0.0.13" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/known-vulnerabilities/seamonkey-1.1/#seamonkey1.1.9" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/known-vulnerabilities/thunderbird-2.0/#thunderbird2.0.0.14" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2008-19/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2008-18/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2008-17/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2008-16/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2008-15/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2008-14/" );
	script_tag( name: "solution", value: "All users should upgrade to the latest versions of Firefox, Thunderbird or
  Seamonkey." );
	script_tag( name: "summary", value: "The remote host is affected by the vulnerabilities described in the
  referenced advisories." );
	script_tag( name: "impact", value: "Mozilla contributors moz_bug_r_a4, Boris Zbarsky, and Johnny Stenback reported
  a series of vulnerabilities which allow scripts from page content to run with
  elevated privileges. moz_bug_r_a4 demonstrated additional variants of MFSA
  2007-25 and MFSA2007-35 (arbitrary code execution through XPCNativeWrapper
  pollution). Additional vulnerabilities reported separately by Boris Zbarsky,
  Johnny Stenback, and moz_bug_r_a4 showed that the browser could be forced to
  run JavaScript code using the wrong principal leading to universal XSS
  and arbitrary code execution." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "2.0.0.13" )){
		report = report_fixed_ver( installed_version: ffVer, fixed_version: "2.0.0.13" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer){
	if(version_is_less( version: smVer, test_version: "1.1.9" )){
		report = report_fixed_ver( installed_version: smVer, fixed_version: "1.1.9" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
tbVer = get_kb_item( "Thunderbird/Win/Ver" );
if(tbVer){
	if(version_is_less( version: tbVer, test_version: "2.0.0.14" )){
		report = report_fixed_ver( installed_version: tbVer, fixed_version: "2.0.0.14" );
		security_message( port: 0, data: report );
	}
}

