CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818522" );
	script_version( "2021-09-24T08:01:25+0000" );
	script_cve_id( "CVE-2021-30858" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-24 08:01:25 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-15 12:55:00 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-14 18:07:04 +0530 (Tue, 14 Sep 2021)" );
	script_name( "Apple Safari Security Update (HT212808)" );
	script_tag( name: "summary", value: "Apple Safari is prone to a code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a use after free issue
  related to improper memory management." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Apple Safari versions before 14.1.2
  build 14611.3.10.1.7 on macOS Mojave and 14.1.2 build 15611.3.10.1.7 on
  macOS Catalina." );
	script_tag( name: "solution", value: "Update to Apple Safari 14.1.2 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212808" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version", "ssh/login/osx_version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[45]\\." ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
buildVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/Safari.app/Contents/Info CFBundleVersion" ) );
if(IsMatchRegexp( osVer, "^10\\.15" )){
	if( version_is_less( version: vers, test_version: "14.1.2" ) ) {
		fix = "Upgrade to 14.1.2 and install update";
	}
	else {
		if(vers == "14.1.2"){
			if(version_is_less( version: buildVer, test_version: "15611.3.10.1.7" )){
				fix = "Apply update from vendor";
				vers = vers + " Build " + buildVer;
			}
		}
	}
}
if(IsMatchRegexp( osVer, "^10\\.14" )){
	if( version_is_less( version: vers, test_version: "14.1.2" ) ) {
		fix = "Upgrade to 14.1.2 and install update";
	}
	else {
		if(vers == "14.1.2"){
			if(version_is_less( version: buildVer, test_version: "14611.3.10.1.7" )){
				fix = "Apply update from vendor";
				vers = vers + " Build " + buildVer;
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

