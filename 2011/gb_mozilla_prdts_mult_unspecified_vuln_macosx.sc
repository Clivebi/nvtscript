if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802515" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-3651" );
	script_bugtraq_id( 50597 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-14 13:12:46 +0530 (Mon, 14 Nov 2011)" );
	script_name( "Mozilla Products Multiple Unspecified Vulnerabilities (MAC OS X)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-48.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause denial of service and
  execute arbitrary code via unspecified vectors." );
	script_tag( name: "affected", value: "Thunderbird version 7.0
  Mozilla Firefox version 7.0" );
	script_tag( name: "insight", value: "The flaws are due to unspecified errors in the browser engine." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 8.0 or later, Upgrade to Thunderbird version to 8.0 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(vers){
	if(version_is_equal( version: vers, test_version: "7.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Equal to 7.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_is_equal( version: vers, test_version: "7.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Equal to 7.0" );
		security_message( port: 0, data: report );
	}
}

