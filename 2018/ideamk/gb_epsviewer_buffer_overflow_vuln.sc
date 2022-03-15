if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112391" );
	script_version( "$Revision: 11852 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 08:12:07 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2018-10-11 21:37:12 +0200 (Thu, 11 Oct 2018)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2013-4979" );
	script_name( "EPS Viewer Buffer Overflow Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_epsviewer_detect_win.sc" );
	script_mandatory_keys( "IdeaMK/EPSViewer/Win/Installed" );
	script_tag( name: "summary", value: "EPS Viewer is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "EPS Viewer is prone to a security vulnerability when processing EPS files.
  This vulnerability could be exploited by a remote attacker to execute arbitrary code on the target machine
  by enticing EPS Viewer users to open a specially crafted EPS file (client-side vulnerability)." );
	script_tag( name: "affected", value: "EPS Viewer up to and including version 3.2." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.secureauth.com/labs/advisories/eps-viewer-buffer-overflow-vulnerability" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:ideamk:eps_viewer";
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "3.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "WillNotFix", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

