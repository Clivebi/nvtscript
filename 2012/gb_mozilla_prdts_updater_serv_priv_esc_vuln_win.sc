if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802867" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-1942", "CVE-2012-1943" );
	script_bugtraq_id( 53803, 53807 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-06-19 12:31:59 +0530 (Tue, 19 Jun 2012)" );
	script_name( "Mozilla Products Updater Service Privilege Escalation Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49368" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49366" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-35.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful attempt could allow local attackers to bypass security restrictions
  and gain the privileges." );
	script_tag( name: "affected", value: "SeaMonkey version 2.9,
  Thunderbird version 12.0 and
  Mozilla Firefox version 12.0 on Windows" );
	script_tag( name: "insight", value: "- Mozilla updater allows to load a local DLL file in a privileged context.

  - The 'Updater.exe' in the Windows Updater Service allows to load an
    arbitrary local wsock32.dll file, which can then be run with the same
    system privileges used by the service." );
	script_tag( name: "summary", value: "This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 13.0 or later, upgrade to SeaMonkey version to 2.10 or later,
  upgrade to Thunderbird version to 13.0 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_is_equal( version: vers, test_version: "12.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Equal to 12.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Seamonkey/Win/Ver" );
if(vers){
	if(version_is_equal( version: vers, test_version: "2.9" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Equal to 2.9" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_is_equal( version: vers, test_version: "12.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Equal to 12.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

