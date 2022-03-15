if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150504" );
	script_version( "2020-12-21T11:30:14+0000" );
	script_tag( name: "last_modification", value: "2020-12-21 11:30:14 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-21 11:26:09 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "openGauss: Configuring an NTP Server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_huawei_opengauss_ssh_login_detect.sc", "compliance_tests.sc" );
	script_mandatory_keys( "huawei/opengauss/detected", "Compliance/Launch" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "The Network Time Protocol (NTP) is used to synchronize time
between clients and servers on the network. By configuring an NTP, you can synchronize the clock of
a PC to the Coordinated Universal Time (UTC) and synchronize system clocks of multiple OSs." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep -P '^\\s*server\\s+{NTP_SERVER}.*$' /etc/ntp.conf";
title = "Configuring an NTP Server";
solution = "Specify a proper NTP server in the /etc/ntp.conf file.
vim /etc/ntp.conf";
default = "{NTP_SERVER}";
test_type = "Manual Check";
compliant = "incomplete";
value = "None";
comment = "Please check the value manually.";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

