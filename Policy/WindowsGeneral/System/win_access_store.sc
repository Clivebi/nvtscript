if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109353" );
	script_version( "2019-12-13T11:11:18+0000" );
	script_tag( name: "last_modification", value: "2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-06-25 10:26:26 +0200 (Mon, 25 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Turn off access to the Store" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting specifies whether to use the Store service
for finding an application to open a file with an unhandled file type or protocol association.

When a user opens a file type or protocol that is not associated with any applications on the computer,
the user is given the choice to select a local application or use the Store service to find an
application.

If you enable this policy setting, the 'Look for an app in the Store' item in the Open With dialog
is removed.

If you disable or do not configure this policy setting, the user is allowed to use the Store service
and the Store item is available in the Open With dialog.

(C) 2015 Microsoft Corporation." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 8.1 or later";
win_min_ver = "6.3";
title = "Turn off access to the Store";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/System/
Internet Communication Management/Internet Communication settings/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\\Policies\\Microsoft\\Windows\\Explorer";
item = "NoUseStoreOpenWith";
reg_path = type + "\\" + key + "!" + item;
default = script_get_preference( "Value" );
if( !policy_verify_win_ver( min_ver: win_min_ver ) ){
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

