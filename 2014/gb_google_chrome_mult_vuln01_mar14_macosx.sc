CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804329" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-6663", "CVE-2013-6664", "CVE-2013-6665", "CVE-2013-6666", "CVE-2013-6667", "CVE-2013-6668" );
	script_bugtraq_id( 65930 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-03-13 11:25:05 +0530 (Thu, 13 Mar 2014)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Mar2014 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An use-after-free error within 'SVGImage::setContainerSize' function and
  'FormAssociatedElement::formRemovedFromTree' function in Blink.

  - Heap buffer overflow within 'ResourceProvider::InitializeSoftware' function.

  - Improper restriction of flash header request within
  'PepperFlashRendererHost::OnNavigate' function.

  - Some unspecified errors related to V8 and other few unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
service, bypass certain security restrictions, execute arbitrary code and
other unspecified impacts." );
	script_tag( name: "affected", value: "Google Chrome version prior to 33.0.1750.146 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 33.0.1750.146 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57194" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1029864" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/03/stable-channel-update.html" );
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
if(version_is_less( version: chromeVer, test_version: "33.0.1750.146" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "33.0.1750.146" );
	security_message( port: 0, data: report );
	exit( 0 );
}

