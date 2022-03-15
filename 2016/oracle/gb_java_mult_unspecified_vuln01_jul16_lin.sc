if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108384" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3550" );
	script_bugtraq_id( 91945, 91996, 91972, 91951 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-07-25 11:28:15 +0530 (Mon, 25 Jul 2016)" );
	script_name( "Oracle Java SE Multiple Unspecified Vulnerabilities-01 July 2016 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A flaw in the Hotspot component.

  - A flaw in the Install component.

  - A flaw in the JAXP component.

  - A flaw in the CORBA component.

  - A flaw in the Networking component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote user
  to access and modify data on the target system, can cause denial of service
  conditions on the target system, a remote or local user can obtain elevated
  privileges on the  target system, also a local user can modify data on the
  target system." );
	script_tag( name: "affected", value: "Oracle Java SE 6 update 115 and prior,
  7 update 101 and prior, and 8 update 92 and prior on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( vers, "^1\\.[6-8]\\." )){
	if(version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.115" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.101" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.92" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

