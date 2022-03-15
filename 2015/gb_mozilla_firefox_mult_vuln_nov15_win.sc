CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806550" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-7200", "CVE-2015-7199", "CVE-2015-7198", "CVE-2015-7197", "CVE-2015-7196", "CVE-2015-7195", "CVE-2015-7194", "CVE-2015-7193", "CVE-2015-7189", "CVE-2015-7188", "CVE-2015-7187", "CVE-2015-4518", "CVE-2015-4515", "CVE-2015-4514", "CVE-2015-4513", "CVE-2015-7183", "CVE-2015-7182", "CVE-2015-7181" );
	script_bugtraq_id( 77412, 77415, 77416 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-11-09 14:40:31 +0530 (Mon, 09 Nov 2015)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities - Nov15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Lack of status checking in CryptoKey interface implementation.

  - Lack of status checking in 'AddWeightedPathSegLists' and
   'SVGPathSegListSMILType::Interpolate' functions.

  - Buffer overflow in the 'rx::TextureStorage11' class in ANGLE graphics
    library.

  - An error in 'web worker' when creating WebSockets.

  - Java plugin can deallocate a JavaScript wrapper when it is still in use,
    which leads to a JavaScript garbage collection crash.

  - An error in URL parsing implementation.

  - Buffer underflow in 'libjar' triggered through a maliciously crafted ZIP
    format file.

  - An error in implementation of CORS cross-origin request algorithm.

  - Buffer overflow in the 'JPEGEncoder' function during script interactions with
    a canvas element.

  - Trailing whitespaces are evaluated differently when parsing IP addresses
    instead of alphanumeric hostnames.

  - Error in 'Add-on SDK' in while creating panel.

  - Error in Reader View implementation in Mozilla Firefox.

  - Error in NTLM-based HTTP authentication.

  - Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox.

  - Multiple memory corruption issues in NSS and NSPR." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service, bypass security restrictions, to
  obtain sensitive information, execute arbitrary script code in a user's
  browser session and some unspecified impacts." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 42.0 on
  Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 42.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-131" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-129" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "42.0" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "42.0" + "\n";
	security_message( data: report );
	exit( 0 );
}

