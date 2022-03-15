if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803118" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-5130", "CVE-2012-5132", "CVE-2012-5133", "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136" );
	script_bugtraq_id( 56684 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-12-04 11:26:39 +0530 (Tue, 04 Dec 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Dec2012 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51437/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/11/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 23.0.1271.91 on Windows" );
	script_tag( name: "insight", value: "- An out-of-bounds read error exists in Skia.

  - A use-after-free error exists in SVG filters and in within printing.

  - Heap-based buffer underflow in the xmlParseAttValueComplex function in
    parser.c in libxmlier, allows remote attackers to cause a denial of service
    or possibly execute arbitrary code via crafted entities in an XML document.

  - A bad cast error exists within input element handling.

  - Browser crash with chunked encoding." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 23.0.1271.91 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
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
if(version_is_less( version: chromeVer, test_version: "23.0.1271.91" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "23.0.1271.91" );
	security_message( port: 0, data: report );
}

