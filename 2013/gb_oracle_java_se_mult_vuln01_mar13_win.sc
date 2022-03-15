if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803327" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-1493", "CVE-2013-0809" );
	script_bugtraq_id( 58296, 58238 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-03-07 18:02:25 +0530 (Thu, 07 Mar 2013)" );
	script_name( "Oracle Java SE Multiple Vulnerabilities -01 March 13 (Windows)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028237" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/438422.php" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/438437.php" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/alert-cve-2013-1493-1915081.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code,
  corrupt memory or cause a denial of service." );
	script_tag( name: "affected", value: "Oracle Java SE Versions 7 Update 15 and earlier, 6 Update 41 and earlier,
  5 Update 40 and earlier on Windows" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Unspecified error in 2D component.

  - Error in color management(CMM) functionality in the 2D component via image
    with crafted raster parameter." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer && IsMatchRegexp( jreVer, "^(1.5|1.6|1.7)" )){
	if(version_in_range( version: jreVer, test_version: "1.7", test_version2: "1.7.0.15" ) || version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.41" ) || version_in_range( version: jreVer, test_version: "1.5", test_version2: "1.5.0.40" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

