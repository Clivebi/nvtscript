if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109520" );
	script_version( "2021-02-12T08:47:50+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 08:47:50 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2018-06-28 16:25:10 +0200 (Thu, 28 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows 10: Configure Windows spotlight on lock screen" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "2;1" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 19.7.8.1 (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 19.7.7.1 (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting lets you configure Windows spotlight on the
lock screen.

If you enable this policy setting, 'Windows spotlight' will be set as the lock screen provider and
users will not be able to modify their lock screen. 'Windows spotlight' will display daily images
from Microsoft on the lock screen.

Additionally, if you check the 'Include content from Enterprise spotlight' checkbox and your
organization has setup an Enterprise spotlight content service in Azure, the lock screen will
display internal messages and communications configured in that service, when available. If your
organization does not have an Enterprise spotlight content service, the checkbox will have no effect.

If you disable this policy setting, Windows spotlight will be turned off and users will no longer be
able to select it as their lock screen. Users will see the default lock screen image and will be
able to select another image, unless you have enabled the 'Prevent changing lock screen image' policy.

If you do not configure this policy, Windows spotlight will be available on the lock screen and will
be selected by default, unless you have configured another default lock screen image using the
'Force a specific default lock screen image' policy.

Note: This policy is only available for Enterprise SKUs

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = policy_microsoft_windows_target_string();
title = "Configure Windows spotlight on lock screen";
solution = "Set following UI path accordingly:
User Configuration/Administrative Templates/Windows Components/Cloud Content/" + title;
type = "HKU";
key = "Software\\Policies\\Microsoft\\Windows\\CloudContent";
item = "ConfigureWindowsSpotlight";
reg_path = type + "\\[SID]\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( "Value" );
if( !policy_verify_win_ver() ) {
	results = policy_report_wrong_os( target_os: target_os );
}
else {
	if( !sids = registry_hku_subkeys() ) {
		results = policy_report_empty_hku();
	}
	else {
		results = policy_match_exact_dword_profiles( key: key, item: item, default: default, sids: sids );
	}
}
value = results["value"];
comment = results["comment"];
compliant = results["compliant"];
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: reg_path, info: comment );
policy_set_kbs( type: test_type, cmd: reg_path, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

