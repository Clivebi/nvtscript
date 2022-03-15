if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108399" );
	script_version( "2020-05-12T13:57:17+0000" );
	script_cve_id( "CVE-2015-4902", "CVE-2015-4903", "CVE-2015-4911", "CVE-2015-4893", "CVE-2015-4883", "CVE-2015-4882", "CVE-2015-4881", "CVE-2015-4872", "CVE-2015-4860", "CVE-2015-4844", "CVE-2015-4843", "CVE-2015-4842", "CVE-2015-4835", "CVE-2015-4806", "CVE-2015-4805", "CVE-2015-4803", "CVE-2015-4734" );
	script_bugtraq_id( 77241, 77194, 77209, 77207, 77161, 77181, 77159, 77211, 77162, 77164, 77160, 77154, 77148, 77126, 77163, 77200, 77192 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-12 13:57:17 +0000 (Tue, 12 May 2020)" );
	script_tag( name: "creation_date", value: "2015-10-27 11:40:31 +0530 (Tue, 27 Oct 2015)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 Oct 2015 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability via different
  vectors." );
	script_tag( name: "affected", value: "Oracle Java SE 6 update 101 and prior, 7
  update 85 and prior, 8 update 60 and prior on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/alerts-086861.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Linux/Ver" );
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
if(IsMatchRegexp( vers, "^1\\.[6-8]" )){
	if(version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.60" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.85" ) || version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.101" )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     " + "Apply the patch" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

