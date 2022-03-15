CPE = "cpe:/a:mozilla:seamonkey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804926" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-1568" );
	script_bugtraq_id( 70116 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-09-30 09:51:51 +0530 (Tue, 30 Sep 2014)" );
	script_name( "Seamonkey RSA Spoof Vulnerability September14 (Macosx)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Seamonkey
  and is prone to spoof vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to improper handling of
  ASN.1 values while parsing RSA signature" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct spoofing attacks." );
	script_tag( name: "affected", value: "Mozilla SeaMonkey before 2.29.1 on Macosx" );
	script_tag( name: "solution", value: "Upgrade to Mozilla seamonkey version 2.29.1
  or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/61540" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=1069405" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/2014/mfsa2014-73.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "SeaMonkey/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!smVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: smVer, test_version: "2.29.1" )){
	report = report_fixed_ver( installed_version: smVer, fixed_version: "2.29.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}

