CPE = "cpe:/a:microsoft:silverlight";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902954" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 58327 );
	script_cve_id( "CVE-2013-0074" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-03-13 12:18:20 +0530 (Wed, 13 Mar 2013)" );
	script_name( "Microsoft Silverlight Remote Code Execution Vulnerability (2814124)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2814124" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-022" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_ms_silverlight_detect.sc" );
	script_mandatory_keys( "Microsoft/Silverlight/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Silverlight version 5." );
	script_tag( name: "insight", value: "The flaw is due to a double-free error when rendering a HTML object, which
  can be exploited via a specially crafted Silverlight application." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS13-022." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(!IsMatchRegexp( vers, "^5\\." )){
	exit( 99 );
}
if(version_in_range( version: vers, test_version: "5.0", test_version2: "5.1.20124.0" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "5.0 - 5.1.20124.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

