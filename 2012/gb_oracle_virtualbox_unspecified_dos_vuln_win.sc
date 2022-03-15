if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803103" );
	script_version( "2020-06-04T13:01:45+0000" );
	script_cve_id( "CVE-2012-3221" );
	script_bugtraq_id( 56045 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-06-04 13:01:45 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2012-10-19 15:10:56 +0530 (Fri, 19 Oct 2012)" );
	script_name( "Oracle VM VirtualBox Unspecified Denial of Service Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_sun_virtualbox_detect_win.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/Win/Ver" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2012.html" );
	script_tag( name: "impact", value: "Successful exploitation allows local users to cause a Denial of Service." );
	script_tag( name: "affected", value: "Oracle VM VirtualBox version 3.2, 4.0 and 4.1 on Windows." );
	script_tag( name: "summary", value: "This host is installed with Oracle VM VirtualBox and is prone to a
  denial of service vulnerability." );
	script_tag( name: "solution", value: "Apply the patch." );
	script_tag( name: "insight", value: "Unspecified error in the VirtualBox Core subcomponent.

  Note: No further information is currently available." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
cpe_list = make_list( "cpe:/a:sun:virtualbox",
	 "cpe:/a:oracle:vm_virtualbox" );
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_equal( version: vers, test_version: "4.1" ) || version_is_equal( version: vers, test_version: "4.0" ) || version_is_equal( version: vers, test_version: "3.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

