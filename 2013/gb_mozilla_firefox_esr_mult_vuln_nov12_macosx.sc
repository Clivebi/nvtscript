if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803631" );
	script_version( "2020-08-17T08:01:28+0000" );
	script_cve_id( "CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196" );
	script_bugtraq_id( 56301, 56302, 56306 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-17 08:01:28 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-11-02 16:08:12 +0530 (Fri, 02 Nov 2012)" );
	script_name( "Mozilla Firefox ESR Multiple Vulnerabilities - November12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51144" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027703" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-90.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to inject scripts and bypass
  certain security restrictions." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 10.x before 10.0.10 on Mac OS X" );
	script_tag( name: "insight", value: "Multiple errors

  - When handling the 'window.location' object.

  - Within CheckURL() function of the 'window.location' object, which can be
    forced to return the wrong calling document and principal.

  - Within handling of 'Location' object can be exploited to bypass security
    wrapper protection." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 10.0.10 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Mozilla/Firefox-ESR/MacOSX/Version" );
if(ffVer && IsMatchRegexp( ffVer, "^10\\.0" )){
	if(version_in_range( version: ffVer, test_version: "10.0", test_version2: "10.0.09" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

