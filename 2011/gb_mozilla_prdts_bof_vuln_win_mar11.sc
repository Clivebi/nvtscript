if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801904" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)" );
	script_cve_id( "CVE-2011-0061" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Buffer Overflow Vulnerability March-11 (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0531" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-09.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code via JPEG image." );
	script_tag( name: "affected", value: "Seamonkey version before 2.0.12
  Thunderbird version before 3.1.8
  Firefox version 3.6.x before 3.6.14" );
	script_tag( name: "insight", value: "Buffer overflow error exists when handling crafted JPEG image, which allows
  remote attackers to execute arbitrary code." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird that are prone
  to buffer overflow vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.14 or later,
  Upgrade to Seamonkey version 2.0.12 or later,
  Upgrade to Thunderbird version 3.1.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "3.6.0", test_version2: "3.6.13" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "3.6.0 - 3.6.13" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer != NULL){
	if(version_is_less( version: smVer, test_version: "2.0.12" )){
		report = report_fixed_ver( installed_version: smVer, fixed_version: "2.0.12" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.1.8" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.8" );
		security_message( port: 0, data: report );
	}
}

