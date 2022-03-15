CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902718" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)" );
	script_cve_id( "CVE-2010-1205", "CVE-2010-2249", "CVE-2011-0170" );
	script_bugtraq_id( 41174 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Apple iTunes Multiple Vulnerabilities (Mac OS X)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4554" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1025152" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce//2011//Mar/msg00000.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "secpod_itunes_detect_macosx.sc" );
	script_mandatory_keys( "Apple/iTunes/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code on
  the target user's system." );
	script_tag( name: "affected", value: "Apple iTunes version prior to 10.2 on Mac OS X version 10.5." );
	script_tag( name: "insight", value: "The flaws are due to the error while handling the crafted files." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes version 10.2 or later." );
	script_tag( name: "summary", value: "This host has installed apple iTunes and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10.5\\." )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "10.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

