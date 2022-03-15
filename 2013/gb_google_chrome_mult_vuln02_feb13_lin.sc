if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803401" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-0839", "CVE-2013-0840", "CVE-2013-0841", "CVE-2013-0842" );
	script_bugtraq_id( 57502 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-02-04 11:39:40 +0530 (Mon, 04 Feb 2013)" );
	script_name( "Google Chrome Multiple Vulnerabilities-02 Feb2013 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51935" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028030" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/01/stable-channel-update_22.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service or possibly have unspecified other impact." );
	script_tag( name: "affected", value: "Google Chrome versions prior to 24.0.1312.56 on Linux" );
	script_tag( name: "insight", value: "Multiple flaws due to

  - Referring freed memory in canvas font handling.

  - Missing URL validation when opening new windows.

  - Unchecked array index in content blocking functionality.

  - Not properly handling %00 characters in path-names." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 24.0.1312.56 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
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
if(version_is_less( version: chromeVer, test_version: "24.0.1312.56" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "24.0.1312.56" );
	security_message( port: 0, data: report );
}

