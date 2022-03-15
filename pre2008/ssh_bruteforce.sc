if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11341" );
	script_version( "2021-02-26T12:02:34+0000" );
	script_bugtraq_id( 2345 );
	script_cve_id( "CVE-2001-0471" );
	script_tag( name: "last_modification", value: "2021-02-26 12:02:34 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "SSH1 SSH Daemon Logging Failure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_openssh_remote_detect.sc", "gb_dropbear_ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "openssh/ssh/detected", "dropbear_ssh/ssh/detected" );
	script_tag( name: "solution", value: "Patch and new version are available from SSH." );
	script_tag( name: "summary", value: "You are running SSH Communications Security SSH 1.2.30, or previous." );
	script_tag( name: "insight", value: "This version does not log repeated login attempts, which
  could allow remote attackers to compromise accounts without detection via a brute force attack." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( tolower( banner ), "openssh" ) || ContainsString( tolower( banner ), "dropbear" )){
	exit( 99 );
}
if(ereg( string: banner, pattern: "^SSH-.*-1\\.([01]|[01]\\..*|2\\.([0-9]|1[0-9]|2[0-9]|30))[^0-9]*$", icase: TRUE )){
	report = report_fixed_ver( installed_version: banner, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

