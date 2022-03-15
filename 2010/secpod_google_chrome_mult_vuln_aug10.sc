if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902096" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-26 15:28:03 +0200 (Thu, 26 Aug 2010)" );
	script_cve_id( "CVE-2010-3120", "CVE-2010-3119", "CVE-2010-3118", "CVE-2010-3117", "CVE-2010-3116", "CVE-2010-3115", "CVE-2010-3114", "CVE-2010-3113", "CVE-2010-3112", "CVE-2010-3111" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Google Chrome multiple vulnerabilities - (Aug10)" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  in the context of the browser, cause denial-of-service conditions, or disclose
  sensitive information." );
	script_tag( name: "affected", value: "Google Chrome version prior to 5.0.375.127 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to:

  - A memory corruption with 'Geolocation' support.

  - An error in supporting the 'Ruby' language.

  - An error in 'Omnibox' implementation, which fails to anticipate entry of
    passwords.

  - An Error in implementing the notifications feature, history feature.

  - A memory corruption in 'MIME' type handling.

  - An error in text-editing implementation, which fails to properly perform
    casts, which has unspecified impact and attack vectors.

  - A memory corruption error  when processing 'SVG' files, file dialogs.

  - An unspecified error in the 'Windows kernel', which has unknown impact and
    attack vectors." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 5.0.375.127 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/" );
	script_xref( name: "URL", value: "http://seclists.org/cert/2010/182" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/current/#google_releases_chrome_5_06" );
	script_xref( name: "URL", value: "http://www.nessus.org/plugins/index.php?view=single&id=48383" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "5.0.375.127" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "5.0.375.127" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

