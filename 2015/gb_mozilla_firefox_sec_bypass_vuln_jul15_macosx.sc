CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805916" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-2727" );
	script_bugtraq_id( 75541 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-07-10 16:09:06 +0530 (Fri, 10 Jul 2015)" );
	script_name( "Mozilla Firefox Multiple Security Bypass Vulnerability - Jul15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read arbitrary files, execute arbitrary JavaScript code and bypass
  security restrictions." );
	script_tag( name: "affected", value: "Mozilla Firefox version 38.0 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 39.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-60" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_equal( version: ffVer, test_version: "38.0" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "39.0" + "\n";
	security_message( data: report );
	exit( 0 );
}

