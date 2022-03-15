if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804864" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-6527", "CVE-2014-6519", "CVE-2014-6476", "CVE-2014-6456" );
	script_bugtraq_id( 70560, 70570, 70531, 70522 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-10-20 13:23:18 +0530 (Mon, 20 Oct 2014)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Oct 2014 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE JRE
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple errors within the Deployment subcomponent.

  - An error in the 'ClassFileParser::parse_classfile_bootstrap_methods_attribute'
    function in share/vm/classfile/classFileParser.cpp script." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to manipulate certain data and execute arbitrary code." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 67 and prior, and 8
  update 20 and prior on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/61609/" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:oracle:jre",
	 "cpe:/a:sun:jre" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^1\\.[78]" )){
	if(version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.67" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.20" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

