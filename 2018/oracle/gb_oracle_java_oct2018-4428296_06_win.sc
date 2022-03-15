if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814402" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2018-3214" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-10-17 11:39:28 +0530 (Wed, 17 Oct 2018)" );
	script_name( "Oracle Java SE Denial of Service Vulnerability(oct2018-4428296)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Check if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in 'Sound'
  component." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause partial denial of service conditions." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.6.0 to 1.6.0.201,
  1.7.0 to 1.7.0.191, 1.8.0 to 1.8.0.182 on Windows." );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
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
if(IsMatchRegexp( vers, "^1\\.[6-8]" )){
	if(( version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.191" ) ) || ( version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.182" ) ) || ( version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.201" ) )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

