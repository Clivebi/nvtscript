CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805626" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710", "CVE-2015-2711", "CVE-2015-2712", "CVE-2015-2713", "CVE-2015-2715", "CVE-2015-2716", "CVE-2015-2717", "CVE-2015-2718", "CVE-2015-0797", "CVE-2015-4496" );
	script_bugtraq_id( 74615, 74611, 76333 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-05-21 18:29:20 +0530 (Thu, 21 May 2015)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities-01 May15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Flaw in WebChannel.jsm module in Mozilla Firefox.

  - Integer overflow in libstagefright in Mozilla Firefox.

  - Buffer overflow in the XML parser in Mozilla Firefox.

  - Race condition in the 'nsThreadManager::RegisterCurrentThread' function in
    Mozilla Firefox.

  - Use-after-free vulnerability in the SetBreaks function in Mozilla Firefox.

  - Flaw in Mozilla Firefox so that does not recognize a referrer policy
    delivered by a referrer META element.

  - Heap-based buffer overflow in the SVGTextFrame class in Mozilla Firefox.

  - Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox.

  - Flaw in asm.js implementation in Mozilla Firefox.

  - Flaw in GStreamer in Mozilla Firefox.

  - Multiple integer overflows in libstagefright in Mozilla Firefox." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially execute arbitrary
  code, bypass security restrictions, bypass origin restrictions, gain
  knowledge of sensitive information, run custom code, cause the server to
  crash and gain privileged access." );
	script_tag( name: "affected", value: "Mozilla Firefox before version 38.0 on
  Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 38.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-46" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_less( version: ffVer, test_version: "38.0" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "38.0" + "\n";
	security_message( data: report );
	exit( 0 );
}

