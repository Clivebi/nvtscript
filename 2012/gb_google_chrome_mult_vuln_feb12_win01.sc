if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802597" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2011-3026", "CVE-2011-3015", "CVE-2011-3027", "CVE-2011-3025", "CVE-2011-3024", "CVE-2011-3023", "CVE-2011-3021", "CVE-2011-3020", "CVE-2011-3019", "CVE-2011-3016", "CVE-2011-3017", "CVE-2011-3018" );
	script_bugtraq_id( 52049, 52031 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-02-21 14:58:55 +0530 (Tue, 21 Feb 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities - February 12 (Windows 01)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48016/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/02/chrome-stable-update.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 17.0.963.56 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to:

  - An integer overflow in libpng, PDF codecs.

  - Bad cast in column handling.

  - Out-of-bounds read in h.264 parsing.

  - Use-after-free with drag and drop.

  - Use-after-free in subframe loading.

  - An error within Native Client validator implementation.

  - Heap buffer overflow while handling MVK file.

  - Use-after-free error while handling database.

  - Heap overflow in path rendering." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 17.0.963.56 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "17.0.963.56" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "17.0.963.56" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

