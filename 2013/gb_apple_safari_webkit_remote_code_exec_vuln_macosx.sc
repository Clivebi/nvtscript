CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803604" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_cve_id( "CVE-2013-0912" );
	script_bugtraq_id( 58388 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-05-27 18:02:13 +0530 (Mon, 27 May 2013)" );
	script_name( "Apple Safari Webkit Remote Code Execution Vulnerability - May13 (Mac OS X)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5701" );
	script_xref( name: "URL", value: "http://prod.lists.apple.com/archives/security-announce/2013/Apr/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attackers to execute arbitrary code via
  crafted SVG document." );
	script_tag( name: "affected", value: "Apple Safari versions prior to 6.0.4 on Mac OS X." );
	script_tag( name: "insight", value: "WebKit contains a type confusion flaw in the 'SVGViewSpec::viewTarget'
  function in WebCore/svg/SVGViewSpec.cpp when handling non-SVG elements." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 6.0.4 or later." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to remote code execution vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(ContainsString( osName, "Mac OS X" )){
	if(version_is_equal( version: osVer, test_version: "10.7.5" ) || version_is_equal( version: osVer, test_version: "10.8.3" )){
		if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
			exit( 0 );
		}
		vers = infos["version"];
		path = infos["location"];
		if(version_is_less( version: vers, test_version: "6.0.4" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 6.0.4 (output of installed version differ from actual Safari version)", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
		exit( 99 );
	}
}
exit( 0 );

