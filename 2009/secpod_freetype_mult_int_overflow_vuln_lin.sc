CPE = "cpe:/a:freetype:freetype";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900631" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-0946" );
	script_name( "FreeType Multiple Integer Overflow Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_freetype_detect_lin.sc" );
	script_mandatory_keys( "FreeType/Linux/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34723" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=491384" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application." );
	script_tag( name: "affected", value: "FreeType version 2.3.9 and prior on Linux." );
	script_tag( name: "insight", value: "Multiple integer overflows are due to inadequate validation of data passed
  into cff/cffload.c, sfnt/ttcmap.c and cff/cffload.c while processing specially crafted fonts." );
	script_tag( name: "summary", value: "This host has FreeType installed and is prone to Multiple Integer Overflow
  vulnerability." );
	script_tag( name: "solution", value: "Apply the fix from the referenced repositories." );
	script_xref( name: "URL", value: "http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=0545ec1ca36b27cb928128870a83e5f668980bc5" );
	script_xref( name: "URL", value: "http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=79972af4f0485a11dcb19551356c45245749fc5b" );
	script_xref( name: "URL", value: "http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=a18788b14db60ae3673f932249cd02d33a227c4e" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: ver, test_version: "2.3.9" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.3.10" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

