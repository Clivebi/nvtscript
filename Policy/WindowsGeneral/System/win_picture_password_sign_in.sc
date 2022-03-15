if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109682" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-09 10:47:49 +0100 (Fri, 09 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: Turn off picture password sign-in" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.8.28.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.8.28.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16.11 Lock Workstation Sessions After Inactivity" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting allows you to control whether a domain user
can sign in using a picture password.

If you enable this policy setting, a domain user can't set up or sign in with a picture password.
If you disable or don't configure this policy setting, a domain user can set up and use a picture password.
Note that the user's domain password will be cached in the system vault when using this feature.

(C) 2015 Microsoft Corporation." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 8.1 or later";
win_min_ver = "6.3";
title = "Turn off picture password sign-in";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/System/Logon/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\\Policies\\Microsoft\\Windows\\System";
item = "BlockDomainPicturePassword";
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

