if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901160" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)" );
	script_cve_id( "CVE-2010-1770", "CVE-2010-1772", "CVE-2010-1773", "CVE-2010-2295", "CVE-2010-2296", "CVE-2010-2297", "CVE-2010-2298", "CVE-2010-2299", "CVE-2010-2300", "CVE-2010-2301", "CVE-2010-2302" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Google Chrome 'WebKit' Multiple Vulnerabilities (Linux) - Sep 10" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40072" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=43902" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=43304" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=43315" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=43307" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/06/stable-channel-update.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a denial of
  service, cross-site-scripting and execution of arbitrary code." );
	script_tag( name: "affected", value: "Google Chrome version prior to 5.0.375.70 on Linux." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Error in 'toAlphabetic' function in 'rendering/RenderListMarker.cpp' in
  WebCore in WebKit.

  - Error in 'page/Geolocation.cpp' which does stop timers associated with
  geolocation upon deletion of a document.

  - Memory corruption in 'font' handling.

  - Error in 'editing/markup.cpp' which fails to validate input passed to
  'innerHTML' property of textarea.

  - Error in 'third_party/WebKit/WebCore/dom/Element.cpp' in 'Element::normalizeAttributes()'
  resulting in DOM mutation events being fired.

  - 'Clipboard::DispatchObject' function which does not properly handle
  'CBF_SMBITMAP objects' in a 'ViewHostMsg_ClipboardWriteObjectsAsync' message
   which lead to illegal memory accesses and arbitrary execution related to
  'Type Confusion' issue.

  - Error in 'rendering/FixedTableLayout.cpp' which leads to denial of service

  - 'Cross-origin bypass' in DOM methods.

  - Error in 'page/EventHandler.cpp' causes Cross-origin keystroke redirection." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 5.0.375.70 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "5.0.375.70" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "5.0.375.70" );
	security_message( port: 0, data: report );
}

