CPE = "cpe:/a:nodejs:node.js";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813476" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2018-1000168" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-05 13:58:00 +0000 (Tue, 05 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-07-10 11:25:10 +0530 (Tue, 10 Jul 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Node.js Denial-of-Service Vulnerability-02 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Node.js and is
  prone to a denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an uninitialized
  read (and a subsequent segfault) error on receiving a malformed ALTSVC frame." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Node.js versions 8.4.x and higher prior to
  8.11.3, 9.x prior to 9.11.2 and 10.x prior to 10.4.1" );
	script_tag( name: "solution", value: "Upgrade to Node.js version 8.11.3 or 9.11.2
  or 10.4.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://nodejs.org/en/blog/vulnerability/june-2018-security-releases/" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_nodejs_detect_macosx.sc" );
	script_mandatory_keys( "Nodejs/MacOSX/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( appPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: appPort, exit_no_version: TRUE )){
	exit( 0 );
}
nodejsVer = infos["version"];
appPath = infos["location"];
if( version_in_range( version: nodejsVer, test_version: "8.4.0", test_version2: "8.11.2" ) ){
	fix = "8.11.3";
}
else {
	if( version_in_range( version: nodejsVer, test_version: "9.0", test_version2: "9.11.1" ) ){
		fix = "9.11.2";
	}
	else {
		if(version_in_range( version: nodejsVer, test_version: "10.0", test_version2: "10.4.0" )){
			fix = "10.4.1";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: nodejsVer, fixed_version: fix, install_path: appPath );
	security_message( port: appPort, data: report );
	exit( 0 );
}
exit( 0 );

