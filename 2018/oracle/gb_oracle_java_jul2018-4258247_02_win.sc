CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813682" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2018-2973", "CVE-2018-2940", "CVE-2018-2952" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-07-18 11:26:47 +0530 (Wed, 18 Jul 2018)" );
	script_name( "Oracle Java SE Security Updates-02 (jul2018-4258247) Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Check if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple unspecified
  errors in components 'Libraries', 'JSSE' and 'Concurrency'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to modify data, partially access data, cause partial denial of service
  conditions." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.8.0.172 and
  earlier, 1.7.0.181 and earlier, 1.6.0.191 and earlier and 10.0 through 10.0.1
  on Windows" );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html" );
	script_xref( name: "URL", value: "https://securitytracker.com/id/1041302" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/java/javase/downloads/index.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
jreVer = infos["version"];
path = infos["location"];
if(( version_in_range( version: jreVer, test_version: "1.6.0", test_version2: "1.6.0.191" ) ) || ( version_in_range( version: jreVer, test_version: "1.8.0", test_version2: "1.8.0.172" ) ) || ( version_in_range( version: jreVer, test_version: "1.7.0", test_version2: "1.7.0.181" ) ) || ( version_in_range( version: jreVer, test_version: "10.0", test_version2: "10.0.1" ) )){
	report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

