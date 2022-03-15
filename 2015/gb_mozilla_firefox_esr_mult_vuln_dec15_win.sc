CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807006" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7210", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7222" );
	script_bugtraq_id( 79279, 79283 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-12-18 10:31:01 +0530 (Fri, 18 Dec 2015)" );
	script_name( "Mozilla Firefox ESR Multiple Vulnerabilities - Dec15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox ESR and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are exists due to:

  - The Multiple unspecified vulnerabilities in the browser engine.

  - An integer underflow in the 'RTPReceiverVideo::ParseRtpPacket' function.

  - The Use-after-free error in WebRTC that occurs due to timing issues in WebRTC
    when closing channels.

  - An integer overflow in the 'mozilla::layers::BufferTextureClient::AllocateForSurface'
    function.

  - An integer overflow in the 'MPEG4Extractor::readMetaData' function in
    'MPEG4Extractor.cpp' script in libstagefright.

  - The Cross-site reading vulnerability through data and view-source URIs.

  - An integer underflow in the 'Metadata::setData' function in 'MetaData.cpp' in
    libstagefright." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service, bypass security restrictions,
  obtain sensitive information, execute arbitrary code and some unspecified
  impacts." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 38.x
  before 38.5 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version
  38.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-134" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-138" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( ffVer, "^38\\." )){
	if(version_is_less( version: ffVer, test_version: "38.5" )){
		report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "38.5" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

