if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803629" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196" );
	script_bugtraq_id( 56301, 56302, 56306 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-11-02 16:08:12 +0530 (Fri, 02 Nov 2012)" );
	script_name( "Mozilla Thunderbird ESR Multiple Vulnerabilities - November12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51144" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027703" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-90.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird-ESR/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to inject scripts and bypass
  certain security restrictions." );
	script_tag( name: "affected", value: "Thunderbird ESR version 10.x before 10.0.10 on Windows" );
	script_tag( name: "insight", value: "Multiple errors

  - When handling the 'window.location' object.

  - Within CheckURL() function of the 'window.location' object, which can be
    forced to return the wrong calling document and principal.

  - Within handling of 'Location' object can be exploited to bypass security
    wrapper protection." );
	script_tag( name: "solution", value: "Upgrade to Thunderbird ESR 10.0.10 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Thunderbird ESR and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Thunderbird-ESR/Win/Ver" );
if(vers && IsMatchRegexp( vers, "^10\\.0" )){
	if(version_in_range( version: vers, test_version: "10.0", test_version2: "10.0.09" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

