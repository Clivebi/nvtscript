if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109720" );
	script_version( "2021-05-14T14:03:39+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 14:03:39 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2019-01-09 08:27:25 +0100 (Wed, 09 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Mounting of udf filesystems" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_lsmod_kernel_modules.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Status", type: "radio", value: "Disabled;Enabled", id: 1 );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 1.1.1.4 Ensure mounting of udf filesystems is disabled (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_tag( name: "summary", value: "The udf filesystem type is the universal disk format used to
implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data
storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer
optical disc formats.

Removing support for unneeded filesystem types reduces the local attack surface of the system. If
this filesystem type is not needed, disable it." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "modprobe -n -v udf; lsmod | grep udf";
title = "Mounting of udf filesystems";
solution = "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf and add the following line:
'install udf /bin/true'.
Run the following command to unload the udf module: 'rmmod udf'.";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Status", id: 1 );
if( !modprobe = policy_modprobe( module: "udf" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Can not run modprobe command on host";
}
else {
	if( get_kb_item( "Policy/linux/lsmod/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not run lsmod command on host";
	}
	else {
		if(get_kb_item( "Policy/linux/module/udf" )){
			loaded = TRUE;
			comment = "Kernel module udf loaded. ";
		}
		if(!IsMatchRegexp( modprobe, "install /bin/true" )){
			no_install_redirect = TRUE;
			comment += "Kernel module udf is not configured to run '/bin/true'.";
		}
		if( loaded || no_install_redirect ) {
			value = "Enabled";
		}
		else {
			value = "Disabled";
		}
		compliant = policy_setting_exact_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

