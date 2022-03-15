CPE = "cpe:/a:unrealircd:unrealircd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811317" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-13649" );
	script_bugtraq_id( 100507 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-31 14:02:54 +0530 (Thu, 31 Aug 2017)" );
	script_name( "UnrealIRCd Local Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with UnrealIRCd
  and is prone to local privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in handling
  of PID file. A PID file after dropping privileges to a non-root account, which
  might allow local users to kill arbitrary processes by leveraging access to
  this non-root account for PID file modification before a root script executes
  a 'kill cat /pathname' command." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow attackers to gain elevated privileges." );
	script_tag( name: "affected", value: "UnrealIRCd versions 4.0.13 and prior." );
	script_tag( name: "solution", value: "Please see the referenced bugreport for
  a workaround how to mitigate this issue within the used start scripts." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://vuldb.com/?id.105695" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2017/q3/343" );
	script_xref( name: "URL", value: "https://bugs.unrealircd.org/view.php?id=4990" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_unrealircd_detect.sc" );
	script_mandatory_keys( "UnrealIRCD/Detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!UnPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!UnVer = get_app_version( cpe: CPE, port: UnPort )){
	exit( 0 );
}
if(version_is_less_equal( version: UnVer, test_version: "4.0.13" )){
	report = report_fixed_ver( installed_version: UnVer, fixed_version: "Please see the solution tag for an available Workaround" );
	security_message( data: report, port: UnPort );
	exit( 0 );
}
exit( 0 );

