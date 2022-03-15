CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806761" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-8478", "CVE-2015-8479", "CVE-2015-8480", "CVE-2015-6769" );
	script_bugtraq_id( 78209, 78416 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-12-07 15:31:40 +0530 (Mon, 07 Dec 2015)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Dec15 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with google chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - 'VideoFramePool::PoolImpl::CreateFrame' function in
    'media/base/video_frame_pool.cc' script does not initialize memory for a
    video-frame data structure.

  - Multiple unspecified vulnerabilities.

  - Multiple cross-origin bypass vulnerabilities.

  - Multiple out of bounds access vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - Integer overflow in Sfntly.

  - Content spoofing vulnerability in Omnibox.

  - Escaping issue in saved pages.

  - Wildcard matching issue in CSP.

  - Multiple scheme bypass vulnerabilities.

  - Type confusion vulnerability in PDFium." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to execute arbitrary code or to cause a denial of service or possibly have
  other impact, bypass the security restrictions and gain access to potentially
  sensitive information." );
	script_tag( name: "affected", value: "Google Chrome versions prior to
  47.0.2526.73 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  47.0.2526.73 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2015/12/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "47.0.2526.73" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     47.0.2526.73" + "\n";
	security_message( data: report );
	exit( 0 );
}

