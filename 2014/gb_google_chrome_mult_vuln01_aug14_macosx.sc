CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804811" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167" );
	script_bugtraq_id( 69201, 69202, 69203 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-08-19 11:25:08 +0530 (Tue, 19 Aug 2014)" );
	script_name( "Google Chrome Multiple Vulnerabilities - 01 Aug14 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Use-after-free vulnerability in websockets/WorkerThreadableWebSocketChannel.cpp
script within the Web Sockets implementation in Blink.

  - An error within SPDY and other multiple unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to disclose potentially
sensitive information, conduct a denial of service attack and potentially
execute arbitrary code or possibly have other impact via unknown vectors." );
	script_tag( name: "affected", value: "Google Chrome version prior to 36.0.1985.143 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome 36.0.1985.143 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59904" );
	script_xref( name: "URL", value: "https://www.hkcert.org/my_url/en/alert/14081401" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/08/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: chromeVer, test_version: "36.0.1985.143" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "36.0.1985.143" );
	security_message( port: 0, data: report );
	exit( 0 );
}

