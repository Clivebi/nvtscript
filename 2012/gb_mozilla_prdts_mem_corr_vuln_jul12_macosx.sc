if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802896" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-1949", "CVE-2012-1960" );
	script_bugtraq_id( 54580, 54572 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-07-24 11:13:01 +0530 (Tue, 24 Jul 2012)" );
	script_name( "Mozilla Products Memory Corruption Vulnerabilities - July12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49965" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027256" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027257" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-42.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-50.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to obtain sensitive
  information, execute arbitrary code in the context of the browser or cause a
  denial of service." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.11
  Thunderbird version 5.0 through 13.0
  Mozilla Firefox version 4.x through 13.0 on Mac OS X" );
	script_tag( name: "insight", value: "- An out-of-bounds read error in the qcms_transform_data_rgb_out_lut_sse2
    function in the QCMS implementation, can be exploited to disclose certain
    process memory via a crafted color profile.

  - Multiple unspecified errors within the browser engine can be exploited to
    corrupt memory." );
	script_tag( name: "summary", value: "This host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 14.0 or later, upgrade to SeaMonkey version to 2.11 or later,
  upgrade to Thunderbird version to 14.0 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "9.0.1" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "13.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "SeaMonkey/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.11" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_in_range( version: vers, test_version: "5.0", test_version2: "9.0.1" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "13.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

