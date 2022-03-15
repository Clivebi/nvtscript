if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801319" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)" );
	script_cve_id( "CVE-2010-1139", "CVE-2009-1564", "CVE-2009-1565" );
	script_bugtraq_id( 39345, 39363, 39364 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "VMware Products Multiple Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Win/Installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/510643" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a heap-based buffer
  overflow via specially crafted video files containing incorrect framebuffer parameters." );
	script_tag( name: "affected", value: "VMware Server version 2.x

  VMware Player version 2.5.x before 2.5.4 build 246459

  VMware Workstation version 6.5.x before 6.5.4 build 246459" );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An integer truncation errors in 'vmnc.dll' when processing 'HexTile' encoded
  video chunks which can be exploited to cause heap-based buffer overflows.

  - A format string vulnerability in 'vmrun' allows users to gain privileges
  via format string specifiers in process metadata." );
	script_tag( name: "summary", value: "The host is installed with VMWare products and are prone to multiple
  vulnerabilities." );
	script_tag( name: "solution", value: "Update to workstation version 6.5.4 build 246459

  Update to VMware player version 6.5.4 build 246459

  Apply workaround for VMware Server version 2.x" );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:vmware:player",
	 "cpe:/a:vmware:workstation",
	 "cpe:/a:vmware:server" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( ContainsString( cpe, "cpe:/a:vmware:player" ) ){
	if(version_in_range( version: vers, test_version: "2.5", test_version2: "2.5.3" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.5.4", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if( ContainsString( cpe, "cpe:/a:vmware:workstation" ) ){
		if(version_in_range( version: vers, test_version: "6.5", test_version2: "6.5.3" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "6.5.4", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
	else {
		if(ContainsString( cpe, "cpe:/a:vmware:server" )){
			if(IsMatchRegexp( vers, "^2\\." )){
				report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the workaround", install_path: path );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

