if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109527" );
	script_version( "2019-12-13T11:11:18+0000" );
	script_tag( name: "last_modification", value: "2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-08-07 12:58:20 +0200 (Tue, 07 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows 10: Support device authentication using certificate" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "0;1" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "Support for device authentication using certificate will require
connectivity to a DC in the device account domain which supports certificate authentication for
computer accounts.

This policy setting allows you to set support for Kerberos to attempt authentication using the
certificate for the device to the domain.

If you enable this policy setting, the device's credentials will be selected based on the following
options:

  - Automatic: Device will attempt to authenticate using its certificate. If the DC does not support
computer account authentication using certificates then authentication with password will be attempted.

  - Force: Device will always authenticate using its certificate. If a DC cannot be found which
support computer account authentication using certificates then authentication will fail.

If you disable this policy setting, certificates will never be used.

If you do not configure this policy setting, Automatic will be used.

(C) Microsoft Corporation 2015.

This script tests for the GPO setting 'Device authentication behavior using certificate'." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = policy_microsoft_windows_target_string();
title = "Support device authentication using certificate";
solution = "Set following UI path accordingly:
System/Kerberos/" + title;
type = "HKLM";
key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters";
item = "DevicePKInitBehavior";
reg_path = type + "\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( "Value" );
if( !policy_verify_win_ver() ) {
	results = policy_report_wrong_os( target_os: target_os );
}
else {
	results = policy_match_exact_reg_dword( key: key, item: item, type: type, default: default );
}
value = results["value"];
comment = results["comment"];
compliant = results["compliant"];
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: reg_path, info: comment );
policy_set_kbs( type: test_type, cmd: reg_path, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

