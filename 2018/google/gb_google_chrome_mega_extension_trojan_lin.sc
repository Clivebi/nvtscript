if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813790" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-10 12:21:10 +0530 (Mon, 10 Sep 2018)" );
	script_name( "Google Chrome MEGA Extension Trojan-Linux" );
	script_tag( name: "summary", value: "This host is installed with Google Chrome
  MEGA extension and tries to detect the trojaned MEGA extension." );
	script_tag( name: "vuldetect", value: "Check if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists as a trojaned version of
  MEGA extension was available in google-chrome webstore for installation and
  update." );
	script_tag( name: "impact", value: "Upon installation or auto update to trojaned
  version, extension would exfiltrate credentials for sites including amazon.com,
  live.com, github.com, google.com (or webstore login), myetherwallet.com,
  mymonero.com, idex.market and HTTP POST requests to any other sites. Then it
  will send them to a server located in Ukraine." );
	script_tag( name: "affected", value: "MEGA extension version 3.39.4 for Chrome on Linux." );
	script_tag( name: "solution", value: "Upgrade to MEGA extension version 3.39.5
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://thehackernews.com/2018/09/mega-file-upload-chrome-extension.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/mega\\.html$", useregex: TRUE, sock: sock );
if(!paths){
	exit( 0 );
}
for path in paths {
	file = chomp( path );
	ver = eregmatch( pattern: "(.*(g|G)oogle.(c|C)hrome.*(e|E)xtensions.*[A-za-z]+/([0-9._]+).*)(M|e)ga/html/mega.html", string: file );
	if(!ver[5]){
		continue;
	}
	version = ver[5];
	filePath = ver[0];
	if(version_is_equal( version: version, test_version: "3.39.4" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "3.39.5", install_path: filePath );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

