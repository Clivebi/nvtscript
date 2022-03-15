CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804154" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-5607" );
	script_bugtraq_id( 63802 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-11-26 09:47:20 +0530 (Tue, 26 Nov 2013)" );
	script_name( "Mozilla Firefox ESR Integer Overflow Vulnerability-01 Nov13 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR and is prone to integer
overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 17.0.11 or 24.1.1 or later." );
	script_tag( name: "insight", value: "The flaw is due to integer overflow in the 'PL_ArenaAllocate' function
in Mozilla Netscape Portable Runtime (NSPR)." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 17.x before 17.0.11 and 24.x before 24.1.1 on
Mac OS X" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55732" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-103.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/current/0105.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "17.0", test_version2: "17.0.10" ) || version_in_range( version: vers, test_version: "24.0", test_version2: "24.1.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

