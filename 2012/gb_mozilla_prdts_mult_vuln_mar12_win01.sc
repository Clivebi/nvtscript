if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802822" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0451", "CVE-2012-0454", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0462" );
	script_bugtraq_id( 52463, 52455, 52457, 52456, 52467 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-03-19 19:20:23 +0530 (Mon, 19 Mar 2012)" );
	script_name( "Mozilla Products Multiple Vulnerabilities - Mar12 (Win 01)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48402" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-12.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-15.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-17.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-18.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-19.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code or inject html code via unknown vectors." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.8
  Thunderbird version 5.0 through 10.0
  Mozilla Firefox version 4.x through 10.0
  Thunderbird ESR version 10.x before 10.0.3
  Mozilla Firefox ESR version 10.x before 10.0.3" );
	script_tag( name: "insight", value: "The flaws are due to

  - An improper write access restriction to the window.fullScreen object.

  - Multiple unspecified vulnerabilities in the browser engine.

  - An improper implementation of the Cascading Style Sheets (CSS) allowing to
    crash the service when accessing keyframe cssText after dynamic
    modification.

  - A use-after-free error within the shlwapi.dll when closing a child window
    that uses the file open dialog.

  - An error when handling Content Security Policy headers." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 11.0 or ESR version 10.0.3 later, Upgrade to SeaMonkey version to 2.8 or later,
  upgrade to Thunderbird version to 11 or ESR version 10.0.3 later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "10.0.2" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "4.0 - 10.0.2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Seamonkey/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.8" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.8" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "5.0", test_version2: "10.0.2" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "5.0 - 10.0.2" );
		security_message( port: 0, data: report );
	}
}

