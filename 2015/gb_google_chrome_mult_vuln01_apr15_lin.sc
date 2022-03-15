CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805360" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-1234", "CVE-2015-1233" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-04-06 14:45:55 +0530 (Mon, 06 Apr 2015)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Apr15 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A race condition in gpu/command_buffer/service/gles2_cmd_decoder.cc that
  is triggered when calculating certain sizes.

  - Unspecified flaws in V8, Gamepad, and IPC." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass sandbox protection mechanisms and execute arbitrary code
  and or cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to
  41.0.2272.118 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  41.0.2272.118 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://msisac.cisecurity.org/advisories/2015/2015-037.cfm" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2015/04/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_less( version: chromeVer, test_version: "41.0.2272.118" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     41.0.2272.118" + "\n";
	security_message( data: report );
	exit( 0 );
}

