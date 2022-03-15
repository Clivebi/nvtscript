CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804152" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-5607" );
	script_bugtraq_id( 63802 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-11-25 21:28:51 +0530 (Mon, 25 Nov 2013)" );
	script_name( "Mozilla Firefox Integer Overflow Vulnerability-01 Nov13 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to integer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 25.0.1 or later." );
	script_tag( name: "insight", value: "The flaw is due to integer overflow in the 'PL_ArenaAllocate' function
in Mozilla Netscape Portable Runtime (NSPR)." );
	script_tag( name: "affected", value: "Mozilla Firefox before version 25.0.1 on Mac OS X" );
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
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "25.0.1" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "25.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}

