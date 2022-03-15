CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805995" );
	script_version( "2020-11-12T09:50:32+0000" );
	script_cve_id( "CVE-2015-7834", "CVE-2015-6763", "CVE-2015-6762", "CVE-2015-6761", "CVE-2015-6760", "CVE-2015-6759", "CVE-2015-6758", "CVE-2015-6757", "CVE-2015-6756", "CVE-2015-6755" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-10-19 13:09:11 +0530 (Mon, 19 Oct 2015)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Oct15 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'ContainerNode::parserInsertBefore' function in
    core/dom/ContainerNode.cpp withn Blink.

  - A use-after-free error in the CPDFSDK_PageView implementation in
    fpdfsdk/src/fsdk_mgr.cpp in PDFium.

  - A use-after-free error in content/browser/service_worker/embedded_worker_instance.cc
    in the ServiceWorker implementation.

  - An error in 'CPDF_Document::GetPage' function in
    fpdfapi/fpdf_parser/fpdf_parser_document.cpp in PDFium.

  - An error in 'shouldTreatAsUniqueOrigin' function in
    platform/weborigin/SecurityOrigin.cpp in Blink.

  - An error in the 'Image11::map' function in renderer/d3d/d3d11/Image11.cpp
    in libANGLE.

  - An error in 'update_dimensions' function in libavcodec/vp8.c in FFmpeg.

  - An error in the 'CSSFontFaceSrcValue::fetch' function in
    core/css/CSSFontFaceSrcValue.cpp in the Cascading Style Sheets (CSS) implementation.

  - Other multiple unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to cause a denial of service or possibly have other impact, bypass the security
  restrictions and gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Google Chrome versions prior to 46.0.2490.71
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  46.0.2490.71 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2015/10/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "46.0.2490.71" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     46.0.2490.71" + "\n";
	security_message( data: report );
	exit( 0 );
}
