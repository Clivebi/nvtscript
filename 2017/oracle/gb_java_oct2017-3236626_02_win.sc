if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812037" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_cve_id( "CVE-2017-10388", "CVE-2017-10293", "CVE-2017-10346", "CVE-2017-10345", "CVE-2017-10285", "CVE-2017-10356", "CVE-2017-10348", "CVE-2017-10295", "CVE-2017-10349", "CVE-2017-10347", "CVE-2017-10274", "CVE-2017-10355", "CVE-2017-10357", "CVE-2017-10281" );
	script_bugtraq_id( 101321, 101338, 101315, 101396, 101319, 101413, 101354, 101384, 101348, 101382, 101333, 101369, 101355, 101378 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2017-10-18 13:03:18 +0530 (Wed, 18 Oct 2017)" );
	script_name( "Oracle Java SE Security Updates (oct2017-3236626) 02 - Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to flaws in the
  'Hotspot', 'RMI ', 'Libraries', 'Smart Card IO', 'Security', 'Javadoc', 'JAXP',
  'Serialization' and 'Networking' components of the application." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to gain elevated privileges, partially access and
  partially modify data, access sensitive data, obtain sensitive information or
  cause a denial of service, ." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.6.0.161 and earlier,
  1.7.0.151 and earlier, 1.8.0.144 and earlier, 9.0 on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( vers, "^(1\\.[6-8]|9)\\." )){
	if(version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.161" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.151" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.144" ) || vers == "9.0"){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

