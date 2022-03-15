CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804318" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2013-6166" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-02-17 17:31:40 +0530 (Mon, 17 Feb 2014)" );
	script_name( "Google Chrome Cross-Site Request Forgery (CSRF) Vulnerability (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to cross-site request
forgery attack." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of 'HTTP Cookie headers' for
restricted character-set." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct the
equivalent of a persistent Logout cross-site request forgery (CSRF) attack." );
	script_tag( name: "affected", value: "Google Chrome version prior to 29 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 29 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q4/117" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2013/04/03/10" );
	script_xref( name: "URL", value: "https://code.google.com/p/chromium/issues/detail?id=238041" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "29.0" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "29.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

