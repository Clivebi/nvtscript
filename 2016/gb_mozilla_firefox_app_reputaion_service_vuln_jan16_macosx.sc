CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807049" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2016-1947" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-01-29 10:26:04 +0530 (Fri, 29 Jan 2016)" );
	script_name( "Mozilla Firefox Application Reputation Service Vulnerability - Jan16 (Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to application reputation service disabling
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to disabling of
  Application Reputation service that leads to removal of the ability of Safe
  browsing to warn against potentially malicious downloads." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to do potentially malicious downloads." );
	script_tag( name: "affected", value: "Mozilla Firefox versions 43.x on
  Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 44
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories" );
	script_xref( name: "URL", value: "http://msisac.cisecurity.org/advisories/2016/2016-018.cfm" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( ffVer, "^43" )){
	if(version_is_less( version: ffVer, test_version: "44.0" )){
		report = report_fixed_ver( installed_version: ffVer, fixed_version: "44.0" );
		security_message( data: report );
		exit( 0 );
	}
}

