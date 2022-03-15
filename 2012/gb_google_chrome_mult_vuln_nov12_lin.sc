if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802491" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-5117", "CVE-2012-5116", "CVE-2012-5128", "CVE-2012-5127", "CVE-2012-5126", "CVE-2012-5125", "CVE-2012-5124", "CVE-2012-5123", "CVE-2012-5122", "CVE-2012-5121", "CVE-2012-5119" );
	script_bugtraq_id( 56413 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-11-09 11:41:50 +0530 (Fri, 09 Nov 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities - Nov2012 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51210/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/11/stable-channel-release-and-beta-channel.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 23.0.1271.64 on Linux" );
	script_tag( name: "insight", value: "- An integer overflow error exists in WebP handling.

  - An error in v8 can be exploited to cause an out-of-bounds array access.

  - Multiple use-after-free error exists in SVG filter, video layout, extension
    tab and plug-in placeholder, handling.

  - An error exists related to integer boundary checks within GPU command
    buffers.

  - An error exists related to inappropriate loading of SVG sub resource in
    'img' context.

  - A race condition error exists in Pepper buffer handling.

  - A type casting error exists in certain input handling.

  - An error in Skia can be exploited to cause an out-of-bounds read.

  - An error in texture handling can be exploited to corrupt memory.

  - An error in v8 can be exploited to corrupt memory." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 23.0.1271.64 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "23.0.1271.64" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "23.0.1271.64" );
	security_message( port: 0, data: report );
}

