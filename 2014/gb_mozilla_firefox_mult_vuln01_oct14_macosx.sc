CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804945" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1586", "CVE-2014-1585", "CVE-2014-1584", "CVE-2014-1583", "CVE-2014-1582", "CVE-2014-1581", "CVE-2014-1580", "CVE-2014-1578", "CVE-2014-1577", "CVE-2014-1576", "CVE-2014-1575", "CVE-2014-1574" );
	script_bugtraq_id( 70427, 70425, 70434, 70424, 70432, 70426, 70431, 70428, 70440, 70430, 70439, 70436 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-10-20 13:02:52 +0530 (Mon, 20 Oct 2014)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities-01 Oct14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Alarm API which does not properly restrict toJSON calls.

  - An error when handling video sharing within a WebRTC session running within an
    iframe.

  - Multiple errors in the Public Key Pinning (PKP) implementation.

  - An use-after-free error when handling text layout related to DirectionalityUtils.

  - An error when repeatedly rendering a GIF image within a canvas element.

  - An out-of-bounds error within the 'get_tile' function when buffering WebM
    format video containing frames.

  - An out-of-bounds error within 'mozilla::dom::OscillatorNodeEngine::ComputeCustom'
    method when interacting with custom waveforms.

  - An error within the 'nsTransformedTextRun' class when handling capitalization
    style changes during CSS parsing.

  - An error when handling camera recording within an iframe related to site
    navigation.

  - Other unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  disclose potentially sensitive information, bypass certain security restrictions,
  conduct denial-of-service attack and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Firefox before version 33.0 on
  Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 33.0
  or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59643/" );
	script_xref( name: "URL", value: "http://msisac.cisecurity.org/advisories/2014/2014-088.cfm" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/2014/mfsa2014-82.html" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/2014/mfsa2014-81.html" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/2014/mfsa2014-76.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "33.0" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "33.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

