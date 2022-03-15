if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109095" );
	script_version( "2021-02-10T14:45:43+0000" );
	script_tag( name: "last_modification", value: "2021-02-10 14:45:43 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "creation_date", value: "2018-04-23 12:03:04 +0200 (Mon, 23 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Prevent the usage of OneDrive for file storage" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.55.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.52.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 13.4 Only Allow Access to Authorized Cloud Storage or Email Providers" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting lets you prevent apps and features from
working with files on OneDrive.

If you enable this policy setting:

  - Users can't access OneDrive from the OneDrive app and file picker.

  - Windows Store apps can't access OneDrive using the WinRT API.

  - OneDrive doesn't appear in the navigation pane in File Explorer.

  - OneDrive files aren't kept in sync with the cloud.

  - Users can't automatically upload photos and videos from the camera roll folder.

If you disable or do not configure this policy setting, apps and features can work with OneDrive
file storage.

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_ver = "6.1";
title = "Prevent the usage of OneDrive for file storage";
solution = "Set following UI path accordingly:
Windows Components/OneDrive/" + title;
type = "HKLM";
key = "SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive";
item = "DisableFileSyncNGSC";
reg_path = type + "\\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference( "Value" );
if( !policy_verify_win_ver( min_ver: win_ver ) ) {
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

