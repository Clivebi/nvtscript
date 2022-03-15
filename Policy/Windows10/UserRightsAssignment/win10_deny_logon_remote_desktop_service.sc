if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109131" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-04-30 13:36:08 +0200 (Mon, 30 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows 10: Deny log on through Remote Desktop Services" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "os_detection.sc", "policy_rsop_userprivilegeright.sc" );
	script_mandatory_keys( "Compliance/Launch", "Host/runs_windows" );
	script_add_preference( name: "Value", type: "entry", value: "Guests, Local account", id: 1 );
	script_xref( name: "Policy", value: "CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.2.20 (L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests' and 'Local account'" );
	script_xref( name: "Policy", value: "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.2.26 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests' and 'Local account' (MS only)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16.8 Disable Any Unassociated Accounts" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment" );
	script_tag( name: "summary", value: "This policy setting determines which users are prevented from
logging on to the device through a Remote Desktop connection through Remote Desktop Services. It is
possible for a user to establish a Remote Desktop connection to a particular server, but not be able
to log on to the console of that server.

(C) Microsoft Corporation 2017." );
	exit( 0 );
}
require("policy_functions.inc.sc");
title = "Deny log on through Remote Desktop Services";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/" + title;
test_type = "WMI_Query";
select = "AccountList";
keyname = "SeDenyRemoteInteractiveLogonRight";
wmi_query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = " + keyname;
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "policy/rsop_securitysetting/kb_smb_wmi_connectinfo/error" ) ){
	value = "Error";
	comment = "Missing connection information to login into the host";
	compliant = "incomplete";
}
else {
	if( get_kb_item( "policy/rsop_securitysetting/rsop_userprivilegeright/error" ) ){
		value = "None";
		comment = "Did not find setting on the host";
		compliant = "no";
	}
	else {
		if( !value = get_kb_item( "policy/rsop_securitysetting/rsop_userprivilegeright/sedenyremoteinteractivelogonright" ) ){
			value = "None";
			comment = "Can not query RSOP_UserPrivilegeRight on the host";
			compliant = "no";
		}
		else {
			compliant = policy_settings_lists_match( value: value, set_points: default, sep: "," );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: wmi_query, info: comment );
policy_set_kbs( type: test_type, cmd: wmi_query, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

