if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803350" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-4209", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-5842", "CVE-2012-5841", "CVE-2012-5829", "CVE-2012-5840", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839" );
	script_bugtraq_id( 56629, 56628, 56633, 56634, 56618, 56614, 56632, 56611, 56631, 56636, 56642, 56637, 56635 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-11-26 12:10:03 +0530 (Mon, 26 Nov 2012)" );
	script_name( "Mozilla SeaMonkey Multiple Vulnerabilities-01 November12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51358" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027791" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027792" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-91.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-92.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-93.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-100.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-101.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-103.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-105.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-106.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Seamonkey/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.14 on Windows" );
	script_tag( name: "insight", value: "- The 'location' property can be accessed through 'top.location' with a
    frame whose name attributes value is set to 'top'.

  - Use-after-free error exists within the functions
    'nsTextEditorState::PrepareEditor', 'gfxFont::GetFontEntry',
    'nsWindow::OnExposeEvent' and 'nsPlaintextEditor::FireClipboardEvent'.

  - An error within the 'evalInSandbox()' when handling the 'location.href'
    property.

  - Error when rendering GIF images." );
	script_tag( name: "solution", value: "Upgrade to SeaMonkey version to 2.14 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Seamonkey and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
seaVer = get_kb_item( "Seamonkey/Win/Ver" );
if(seaVer){
	if(version_is_less( version: seaVer, test_version: "2.14" )){
		report = report_fixed_ver( installed_version: seaVer, fixed_version: "2.14" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

