CPE = "cpe:/a:adobe:acrobat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801104" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3431" );
	script_bugtraq_id( 35148 );
	script_name( "Adobe Acrobat PDF File Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2009-3431" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/Win/Installed" );
	script_tag( name: "impact", value: "Successful attacks results in Denial of Service." );
	script_tag( name: "affected", value: "Adobe Acrobat version 9.1.1 and prior on Windows." );
	script_tag( name: "insight", value: "A Stack consumption error exists when handling a PDF file containing a large
  number of '[' characters to the alert method." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat version 9.1.2 or later." );
	script_tag( name: "summary", value: "This host has Adobe Acrobat or Adobe Acrobat Reader installed and
  is prone to Denial of Service vulnerability." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "9.1.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.1.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

