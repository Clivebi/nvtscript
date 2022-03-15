CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804618" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746", "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3152", "CVE-2014-3803" );
	script_bugtraq_id( 67790, 67517, 67582 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-06-04 10:20:11 +0530 (Wed, 04 Jun 2014)" );
	script_name( "Google Chrome Multiple Vulnerabilities - 01 June14 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to:

  - A use-after-free error exists in 'StyleElement::removedFromDocument' function
within core/dom/StyleElement.cpp.

  - An integer overflow error exists in 'AudioInputRendererHost::OnCreateStream'
function in media/audio_input_renderer_host.cc.

  - A use-after-free error exists within SVG.

  - An error within media filters  in 'InMemoryUrlProtocol::Read'.

  - An error in 'DocumentLoader::maybeCreateArchive' function related to a local
MHTML file.

  - An error in 'ScrollView::paint' function related to scroll bars.

  - Multiple unspecified errors exist.

  - An integer overflow error in 'LCodeGen::PrepareKeyedOperand' function in
arm/lithium-codegen-arm.cc within v8.

  - Some error in speech API within Blink." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct a denial of
service, inject arbitrary web script or HTML, spoof the UI, enable microphone
access and obtain speech-recognition text and possibly have other unspecified
impact." );
	script_tag( name: "affected", value: "Google Chrome version prior to 35.0.1916.114 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome 35.0.1916.114 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/05/stable-channel-update_20.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: chromeVer, test_version: "35.0.1916.114" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "35.0.1916.114" );
	security_message( port: 0, data: report );
	exit( 0 );
}

