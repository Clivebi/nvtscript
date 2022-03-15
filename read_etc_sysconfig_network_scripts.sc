if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150182" );
	script_version( "2020-03-25T11:27:13+0000" );
	script_tag( name: "last_modification", value: "2020-03-25 11:27:13 +0000 (Wed, 25 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-25 11:20:57 +0000 (Wed, 25 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read /etc/sysconfig/network-scripts/ (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/s1-networkscripts-interfaces" );
	script_tag( name: "summary", value: "Interface configuration files control the software interfaces
for individual network devices. As the system boots, it uses these files to determine what
interfaces to bring up and how to configure them. These files are usually named ifcfg-name, where
name refers to the name of the device that the configuration file controls.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
directory = "/etc/sysconfig/network-scripts/";
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/" + directory + "/ERROR", value: TRUE );
	set_kb_item( name: "Policy/linux/" + directory + "/stat/ERROR", value: TRUE );
	exit( 0 );
}
policy_read_files_in_directory( socket: sock, directory: directory );
exit( 0 );

