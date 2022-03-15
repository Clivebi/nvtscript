CPE = "cpe:/a:trendmicro:internet_security";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808638" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-1225", "CVE-2016-1226" );
	script_bugtraq_id( 90999 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-05 12:51:56 +0530 (Fri, 05 Aug 2016)" );
	script_name( "TrendMicro Internet Security Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with TrendMicro Internet
  Security and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple input
  validation errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to access files on the device and also to execute arbitrary script
  on the products." );
	script_tag( name: "affected", value: "TrendMicro Internet Security version 8 and 10" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN48789425/index.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_trendmicro_internet_security_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "TrendMicro/IS/Installed" );
	script_xref( name: "URL", value: "https://esupport.trendmicro.com/support/vb/solution/ja-jp/1113880.aspx" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
treVer = infos["version"];
sysPath = infos["location"];
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "Titanium\\plugin\\plugDaemonHost.dll" );
if(!sysVer){
	exit( 0 );
}
if(version_is_equal( version: treVer, test_version: "8.0" ) || version_is_equal( version: treVer, test_version: "10.0" )){
	if( IsMatchRegexp( treVer, "^8" ) ){
		minRequireVer = "8.0.0.2062";
	}
	else {
		minRequireVer = "9.0.0.1265";
	}
	if(version_is_less( version: sysVer, test_version: minRequireVer )){
		report = report_fixed_ver( installed_version: treVer, fixed_version: "Apply the Patch", install_path: sysPath );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

