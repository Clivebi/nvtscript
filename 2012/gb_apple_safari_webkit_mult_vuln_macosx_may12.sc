CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802797" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_cve_id( "CVE-2011-3046", "CVE-2011-3056", "CVE-2012-0672", "CVE-2012-0676" );
	script_bugtraq_id( 52369, 53407, 53404, 53446 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2012-05-18 19:42:59 +0530 (Fri, 18 May 2012)" );
	script_name( "Apple Safari Webkit Multiple Vulnerabilities - May 12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5282" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47292/" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2012/May/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to conduct cross site
  scripting attacks, bypass certain security restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Apple Safari versions prior to 5.1.7 on Mac OS X." );
	script_tag( name: "insight", value: "The flaws are due to

  - Multiple cross site scripting and memory corruption issues in webkit.

  - A state tracking issue existed in WebKit's handling of forms." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 5.1.7 or later." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.1.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 5.1.7 (output of installed version differ from actual Safari version)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

