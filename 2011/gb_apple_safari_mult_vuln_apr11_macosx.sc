CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802234" );
	script_version( "2020-03-02T13:53:38+0000" );
	script_tag( name: "last_modification", value: "2020-03-02 13:53:38 +0000 (Mon, 02 Mar 2020)" );
	script_tag( name: "creation_date", value: "2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)" );
	script_cve_id( "CVE-2011-1290", "CVE-2011-1344" );
	script_bugtraq_id( 46822, 46849 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Apple Safari Multiple Vulnerabilities - April 2011 (Mac OS X)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4596" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2011/Apr/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the browser." );
	script_tag( name: "affected", value: "Apple Safari versions prior to 5.0.5." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An integer overflow error in WebKit related to CSS 'style handling',
    nodesets, and a length value.

  - A use-after-free error within WebKit when handling WBR tags." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 5.0.5 or later." );
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
if(version_is_less( version: vers, test_version: "5.0.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.0.5", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

