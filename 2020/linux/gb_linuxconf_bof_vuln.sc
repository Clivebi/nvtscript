if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10135" );
	script_version( "2020-10-01T11:33:30+0000" );
	script_tag( name: "last_modification", value: "2020-10-01 11:33:30 +0000 (Thu, 01 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-28 09:12:43 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_cve_id( "CVE-2000-0017" );
	script_name( "LinuxConf Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "linuxconf_detect.sc" );
	script_mandatory_keys( "linuxconf/detected" );
	script_tag( name: "summary", value: "LinuxConf is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker
  to execute arbitrary commands on the target machine as the root user." );
	script_tag( name: "solution", value: "Disable Linuxconf access from the network by
  using a firewall. If you do not need Linuxconf use the Linuxconf utility to disable it." );
	script_xref( name: "URL", value: "http://www.securiteam.com/exploits/Linuxconf_contains_remotely_exploitable_buffer_overflow.html" );
	exit( 0 );
}
CPE = "cpe:/a:jacques_gelinas:linuxconf";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!location = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
report = "Linuxconf was detected on the target system.";
security_message( data: report, port: port );
exit( 0 );

