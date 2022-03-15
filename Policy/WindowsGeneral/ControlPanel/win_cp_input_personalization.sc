if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109297" );
	script_version( "2021-02-04T13:14:20+0000" );
	script_tag( name: "last_modification", value: "2021-02-04 13:14:20 +0000 (Thu, 04 Feb 2021)" );
	script_tag( name: "creation_date", value: "2018-06-15 09:30:22 +0200 (Fri, 15 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Allow Input Personalization" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "0;1" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "Microsoft provides both a device-based speech recognition feature
and a cloud-based (online) speech recognition service in regions where Cortana is available. Turning
on the Online speech recognition setting lets you use Microsoft cloud-based speech recognition in
Cortana, the Mixed Reality Portal, dictation in Windows from the software keyboard, supported
Microsoft Store apps, and over time, in other parts of Windows.

When you use the Microsoft cloud-based speech recognition service, Microsoft collects and uses your
voice recordings to create a text transcription of the spoken words in the voice data.

(C) Microsoft Corporation 2020." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 8.1 or later";
win_min_ver = "6.3";
title = "Allow input personalization";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Control Panel/Regional and Language Options/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\\Policies\\Microsoft\\InputPersonalization";
item = "AllowInputPersonalization";
reg_path = type + "\\" + key + "!" + item;
default = script_get_preference( "Value" );
if( !policy_verify_win_ver( min_ver: win_min_ver ) ) {
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

