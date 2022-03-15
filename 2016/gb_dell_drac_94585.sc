if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140083" );
	script_bugtraq_id( 94585 );
	script_cve_id( "CVE-2016-5685" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-03-05 10:52:42 +0000 (Fri, 05 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-11-30 13:23:23 +0100 (Wed, 30 Nov 2016)" );
	script_version( "2021-03-05T10:52:42+0000" );
	script_name( "Dell iDRAC7 and iDRAC8 Devices Code Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_dell_drac_detect.sc" );
	script_mandatory_keys( "dell_idrac/installed", "dell_idrac/generation" );
	script_xref( name: "URL", value: "http://en.community.dell.com/techcenter/extras/m/white_papers/20443326" );
	script_tag( name: "vuldetect", value: "Checks the firmware version." );
	script_tag( name: "solution", value: "Update to firmware version 2.40.40.40 or later." );
	script_tag( name: "summary", value: "Dell iDRAC7 and iDRAC8 devices allow authenticated users
  to gain Bash shell access through a string injection." );
	script_tag( name: "affected", value: "Dell iDRAC7 and iDRAC8 devices with firmware version
  before 2.40.40.40." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:dell:idrac7",
	 "cpe:/a:dell:idrac8" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
generation = get_kb_item( "dell_idrac/generation" );
if(!generation){
	exit( 0 );
}
cpe = "cpe:/a:dell:idrac" + generation;
if(!version = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.40.40.40" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.40.40.40" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

