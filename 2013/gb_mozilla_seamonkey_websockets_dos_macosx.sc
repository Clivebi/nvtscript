if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803393" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2012-4191" );
	script_bugtraq_id( 55889 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)" );
	script_name( "Mozilla Seamonkey 'WebSockets' Denial of Service Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50856" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50935" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-88.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "SeaMonkey/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary code via unspecified vectors." );
	script_tag( name: "affected", value: "SeaMonkey versions before 2.13.1 on Mac OS X." );
	script_tag( name: "insight", value: "Error in the WebSockets implementation, allows remote attackers to cause a
  denial of service." );
	script_tag( name: "solution", value: "Upgrade to SeaMonkey version to 2.13.1 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Seamonkey and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "SeaMonkey/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.13.1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.13.1" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

