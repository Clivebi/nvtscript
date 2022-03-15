if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118169" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2020-14556", "CVE-2020-14581" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2021-08-25 09:18:34 +0200 (Wed, 25 Aug 2021)" );
	script_name( "Oracle Java SE Security Updates(jul2020) 04 - Linux" );
	script_tag( name: "summary", value: "Oracle Java SE is prone to multiple security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to errors in the components 'Libraries'
  and '2D'." );
	script_tag( name: "impact", value: "Successful attacks of this vulnerability can result in unauthorized
  update, insert or delete access to some accessible data as well as unauthorized read access to a
  subset of accessible data." );
	script_tag( name: "affected", value: "Oracle Java SE version 8u251 (1.8.0.251) and earlier, 11.0.7
  and earlier, 14.0.1 and earlier on Linux." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujul2020.html#AppendixJAVA" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Oracle/Java/JDK_or_JRE/Linux/detected" );
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
if(version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.251" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.7" ) || version_in_range( version: vers, test_version: "14.0", test_version2: "14.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

