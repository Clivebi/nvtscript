if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803357" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-2632" );
	script_bugtraq_id( 58697 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-04-02 11:31:23 +0530 (Tue, 02 Apr 2013)" );
	script_name( "Google Chrome Denial of Service Vulnerability - April 13 (Mac OS X)" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-2632" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/03/dev-channel-update_18.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause denial-of-service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 27.0.1444.3 on MAC OS X" );
	script_tag( name: "insight", value: "User-supplied input is not properly sanitized when parsing JavaScript in
  'Google V8' JavaScript Engine." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 27.0.1444.3 or later." );
	script_tag( name: "summary", value: "The host is running Google Chrome and is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/MacOSX/Version" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "27.0.1444.3" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "27.0.1444.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}

