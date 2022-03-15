if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801739" );
	script_version( "2020-06-09T06:40:15+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 06:40:15 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)" );
	script_cve_id( "CVE-2011-0777", "CVE-2011-0778", "CVE-2011-0779", "CVE-2011-0780", "CVE-2011-0781", "CVE-2011-0783", "CVE-2011-0784" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Google Chrome multiple vulnerabilities - February 11(Windows)" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/02/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code
  in the context of the browser or cause denial-of-service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 9.0.597.84" );
	script_tag( name: "insight", value: "The flaws are due to

  - Use-after-free error in image loading

  - Not properly restricting drag and drop operations

  - PDF event handler, which does not properly interact with print operations

  - Not properly handling a missing key in an extension

  - Not properly handling autofill profile merging

  - Browser crash with bad volume setting

  - Race condition in audio handling" );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 9.0.597.84 or later." );
	script_tag( name: "summary", value: "The host is running Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "9.0.597.84" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "9.0.597.84" );
	security_message( port: 0, data: report );
}

