if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801540" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-11-18 06:30:08 +0100 (Thu, 18 Nov 2010)" );
	script_cve_id( "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4199", "CVE-2010-4201", "CVE-2010-4202", "CVE-2010-4203", "CVE-2010-4204", "CVE-2010-4205", "CVE-2010-4206", "CVE-2010-4008" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 18:24:00 +0000 (Fri, 31 Jul 2020)" );
	script_name( "Google Chrome multiple vulnerabilities - November 10(Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2889" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=51602" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/11/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to execute arbitrary code
  in the context of the browser, cause denial-of-service condition, carry out
  spoofing attacks, gain access to sensitive information, and bypass intended security restrictions." );
	script_tag( name: "affected", value: "Google Chrome version prior to 7.0.517.44 on Windows." );
	script_tag( name: "insight", value: "The flaws are due to

  - A use-after-free error related to text editing

  - A memory corruption error when handling an overly large text area

  - A bad cast with the SVG use element

  - An invalid memory read in XPath handling

  - A use-after-free error related to text control selections

  - A integer overflows in font handling on Linux

  - A memory corruption error in libvpx

  - A bad use of destroyed frame objects

  - A type confusions with event objects

  - An out-of-bounds array access when handling SVGs." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 7.0.517.44 or later." );
	script_tag( name: "summary", value: "The host is running Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "7.0.517.44" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "7.0.517.44" );
	security_message( port: 0, data: report );
}

