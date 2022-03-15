CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813591" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_cve_id( "CVE-2018-14438" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-17 13:56:00 +0000 (Mon, 17 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-07-30 16:58:30 +0530 (Mon, 30 Jul 2018)" );
	script_name( "Wireshark 'non-NULL DACL' Access Control Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to access control vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to create_app_running_mutex
  function in wsutil/file_util.c calling SetSecurityDescriptorDacl to set
  a NULL DACL." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to modify the access control arbitrarily." );
	script_tag( name: "affected", value: "Wireshark version through 2.6.6 on Mac OS X." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14921" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
wirversion = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: wirversion, test_version: "2.6.6" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "None", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

