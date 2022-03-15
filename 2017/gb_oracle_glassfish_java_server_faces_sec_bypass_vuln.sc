CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810747" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2017-3626", "CVE-2017-10400", "CVE-2016-3092", "CVE-2018-2911", "CVE-2018-3152" );
	script_bugtraq_id( 97896, 101383, 91453 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)" );
	script_tag( name: "creation_date", value: "2017-04-19 13:45:58 +0530 (Wed, 19 Apr 2017)" );
	script_name( "Oracle GlassFish Server Multiple Security Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Oracle GlassFish Server
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to unspecified errors in
  the Java Server Faces, Administration, Web Container (Apache Commons FileUpload)
  and Administration Graphical User Interface sub-components." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  users unauthorized read access to a subset of Oracle GlassFish Server accessible
  data, conduct a denial-of-service condition and have an impact on confidentiality
  and integrity." );
	script_tag( name: "affected", value: "Oracle GlassFish Server versions 3.1.2" );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2017verbose-3236619.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html#AppendixFMW" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!dbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE, port: dbPort )){
	exit( 0 );
}
dbVer = infos["version"];
dbPath = infos["location"];
if(IsMatchRegexp( dbVer, "^3\\." )){
	if(version_is_equal( version: dbVer, test_version: "3.1.2" )){
		report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch", install_path: dbPath );
		security_message( data: report, port: dbPort );
		exit( 0 );
	}
}
exit( 99 );

