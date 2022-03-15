if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802514" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-3654", "CVE-2011-3653", "CVE-2011-3652" );
	script_bugtraq_id( 50602, 50592, 50600 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-14 12:41:48 +0530 (Mon, 14 Nov 2011)" );
	script_name( "Mozilla Products Multiple Vulnerabilities (MAC OS X)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-48.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service and
  execute arbitrary code via unspecified vectors." );
	script_tag( name: "affected", value: "Thunderbird version prior to 8.0
  Mozilla Firefox version prior to 8.0" );
	script_tag( name: "insight", value: "The flaws are due to

  - Error in browser engine, which fails to properly handle links from SVG
    mpath elements to non-SVG elements.

  - Error in browser engine, which fails to properly allocate memory.

  - Not properly interacting with the GPU memory behavior of a certain driver
    for Intel integrated GPUs." );
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
	if(version_is_less( version: vers, test_version: "8.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "8.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "8.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "8.0" );
		security_message( port: 0, data: report );
	}
}

