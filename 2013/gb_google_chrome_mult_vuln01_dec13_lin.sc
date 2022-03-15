CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804164" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-6635", "CVE-2013-6634", "CVE-2013-6640", "CVE-2013-6636", "CVE-2013-6639", "CVE-2013-6638", "CVE-2013-6637" );
	script_bugtraq_id( 64078 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-10 11:30:29 +0530 (Tue, 10 Dec 2013)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Dec2013 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 31.0.1650.63 or later." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Use-after-free vulnerability in the editing implementation in Blink.

  - An error in 'OneClickSigninHelper::ShowInfoBarIfPossible' function when
handling the 302 HTTP status in sync.

  - An out-of-bounds read error in 'DehoistArrayIndex' function in
'hydrogen-dehoist.cc' in V8.

  - An error in 'FrameLoader::notifyIfInitialDocumentAccessed' function in
'core/loader/FrameLoader.cpp' in Blink.

  - An out-of-bounds write error in 'DehoistArrayIndex' function in
'hydrogen-dehoist.cc' in V8.

  - An unspecified error in runtime.cc in V8." );
	script_tag( name: "affected", value: "Google Chrome version prior to 31.0.1650.63 on Linux." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
service, spoofing, session fixation attacks, compromise a user's system and
other attacks may also be possible." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55942" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1029442" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/12/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "31.0.1650.63" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "31.0.1650.63" );
	security_message( port: 0, data: report );
	exit( 0 );
}

