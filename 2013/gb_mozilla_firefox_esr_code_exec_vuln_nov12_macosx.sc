if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803348" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2012-4210" );
	script_bugtraq_id( 56646 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-04-01 17:03:21 +0530 (Mon, 01 Apr 2013)" );
	script_name( "Mozilla Firefox ESR Code Execution Vulnerabilities - November12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51358" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027791" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027792" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-104.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain privileges or execute
  arbitrary code in the context of the browser." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 10.x before 10.0.11 on Mac OS X" );
	script_tag( name: "insight", value: "An error within Style Inspector when parsing style sheets can be exploited
  to execute HTML and CSS code in chrome privileged context." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR 10.0.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR and is prone to multiple
  code execution vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
fesrVer = get_kb_item( "Mozilla/Firefox-ESR/MacOSX/Version" );
if(fesrVer && IsMatchRegexp( fesrVer, "^10\\.0" )){
	if(version_in_range( version: fesrVer, test_version: "10.0", test_version2: "10.0.10" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

