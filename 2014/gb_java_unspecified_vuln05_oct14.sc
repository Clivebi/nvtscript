if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804866" );
	script_version( "2020-05-12T13:57:17+0000" );
	script_cve_id( "CVE-2014-6504" );
	script_bugtraq_id( 70564 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-12 13:57:17 +0000 (Tue, 12 May 2020)" );
	script_tag( name: "creation_date", value: "2014-10-20 14:00:18 +0530 (Mon, 20 Oct 2014)" );
	script_name( "Oracle Java SE JRE Unspecified Vulnerability-05 Oct 2014 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE JRE
  and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error related to C2
  optimizations and range checks in the Hotspot subcomponent." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose sensitive information." );
	script_tag( name: "affected", value: "Oracle Java SE 5.0u71 and prior, 6u81 and
  prior, and 7u67 and prior on Windows." );
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
if(IsMatchRegexp( vers, "^1\\.[5-7]" )){
	if(version_in_range( version: vers, test_version: "1.5.0", test_version2: "1.5.0.71" ) || version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.81" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.67" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

