if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803611" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-1681", "CVE-2013-1680", "CVE-2013-1679", "CVE-2013-1678", "CVE-2013-1677", "CVE-2013-1676", "CVE-2013-1675", "CVE-2013-1674", "CVE-2013-1672", "CVE-2013-1670", "CVE-2013-0801" );
	script_bugtraq_id( 59862, 59861, 59860, 59864, 59868, 59863, 59858, 59859, 59872, 59865, 59855 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-27 13:20:15 +0530 (Mon, 27 May 2013)" );
	script_name( "Mozilla Thunderbird ESR Multiple Vulnerabilities -01 May13 (Windows)" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028555" );
	script_xref( name: "URL", value: "http://www.dhses.ny.gov/ocs/advisories/2013/2013-051.cfm" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird-ESR/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise
  a user's system." );
	script_tag( name: "affected", value: "Mozilla Thunderbird ESR version 17.x before 17.0.6 on Windows" );
	script_tag( name: "insight", value: "- Unspecified vulnerabilities in the browser engine.

  - The Chrome Object Wrapper (COW) implementation does not prevent
    acquisition of chrome privileges.

  - 'nsDOMSVGZoomEvent::mPreviousScale' and 'nsDOMSVGZoomEvent::mNewScale'
    functions do not initialize data structures.

  - Errors in 'SelectionIterator::GetNextSegment',
   'gfxSkipCharsIterator::SetOffsets' and '_cairo_xlib_surface_add_glyph'
   functions.

  - Use-after-free vulnerabilities in following functions,
    'nsContentUtils::RemoveScriptBlocker', 'nsFrameList::FirstChild', and
    'mozilla::plugins::child::_geturlnotify'." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird ESR version 17.0.6 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Thunderbird ESR and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Thunderbird-ESR/Win/Ver" );
if(vers && IsMatchRegexp( vers, "^17\\.0" )){
	if(version_in_range( version: vers, test_version: "17.0", test_version2: "17.0.5" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

