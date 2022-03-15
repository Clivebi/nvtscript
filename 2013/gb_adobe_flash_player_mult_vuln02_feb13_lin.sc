if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803409" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-14 13:44:47 +0530 (Thu, 14 Feb 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642", "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0647", "CVE-2013-0649", "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368", "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1372", "CVE-2013-1373", "CVE-2013-1374" );
	script_bugtraq_id( 57929, 57926, 57925, 57923, 57933, 57916, 57927, 57930, 57920, 57924, 57922, 57918, 57919, 57912, 57917 );
	script_name( "Adobe Flash Player Multiple Vulnerabilities -02 Feb13 (Linux)" );
	script_xref( name: "URL", value: "https://lwn.net/Articles/537746" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52166" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-05.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause buffer overflow,
  remote code execution and corrupt system memory." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 10.3.183.61 and 11.x prior to 11.2.202.270
  on Linux" );
	script_tag( name: "insight", value: "Multiple flaws due to

  - Dereference already freed memory

  - Use-after-free errors

  - Integer overflow and some unspecified error." );
	script_tag( name: "solution", value: "Update to version 11.2.202.270 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "10.3.183.61" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.2.202.269" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

