if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802992" );
	script_version( "2020-08-17T08:01:28+0000" );
	script_cve_id( "CVE-2012-4192", "CVE-2012-4193" );
	script_bugtraq_id( 55889 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-17 08:01:28 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-15 17:11:30 +0530 (Mon, 15 Oct 2012)" );
	script_name( "Mozilla Firefox Security Bypass Vulnerabilities - Oct 12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50856" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50935" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-89.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to bypass the Same Origin Policy
  and read the properties of a Location object via a crafted web site." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 16.0.1 on Mac OS X" );
	script_tag( name: "insight", value: "Security wrappers are unwrapped without doing a security check in
  defaultValue(). This can allow for improper access to the Location object." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 16.0.1 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "16.0.1" )){
		report = report_fixed_ver( installed_version: ffVer, fixed_version: "16.0.1" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

