if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801777" );
	script_version( "2020-06-05T10:36:02+0000" );
	script_tag( name: "last_modification", value: "2020-06-05 10:36:02 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "creation_date", value: "2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)" );
	script_cve_id( "CVE-2011-1301", "CVE-2011-1302" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Google Chrome 'GPU process' Multiple Code Execution Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/04/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Google Chrome version prior to 10.0.648.205 on Linux" );
	script_tag( name: "insight", value: "The flaws are due to

  - Use-after-free in the vulnerability GPU process.

  - Heap-based buffer overflow in the GPU process." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 10.0.648.205 or later." );
	script_tag( name: "summary", value: "The host is installed Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "10.0.648.205" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "10.0.648.205" );
	security_message( port: 0, data: report );
}

