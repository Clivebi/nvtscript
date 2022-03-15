CPE = "cpe:/a:measuresoft:scadapro_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803949" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2012-1824" );
	script_bugtraq_id( 53681 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-10-03 12:30:46 +0530 (Thu, 03 Oct 2013)" );
	script_name( "Measuresoft ScadaPro Server DLL Code Execution Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Measuresoft ScadaPro Server and is prone to code
execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 4.0.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "A flaw exists in the application, which does not directly specify the fully
qualified path to a dynamic-linked library." );
	script_tag( name: "affected", value: "Measuresoft ScadaPro Server before 4.0.0" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code on the
system via a specially-crafted library." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/75860" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICSA-12-145-01.pdf" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_measuresoft_scadapro_server_detect.sc" );
	script_mandatory_keys( "ScadaProServer/Win/Ver" );
	script_xref( name: "URL", value: "http://www.measuresoft.com/download/current_release.aspx" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!scadaprosvrVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: scadaprosvrVer, test_version: "4.0.0" )){
	report = report_fixed_ver( installed_version: scadaprosvrVer, fixed_version: "4.0.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

