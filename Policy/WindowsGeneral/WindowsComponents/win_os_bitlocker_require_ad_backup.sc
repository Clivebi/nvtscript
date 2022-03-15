if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109396" );
	script_version( "2019-12-16T11:36:02+0000" );
	script_tag( name: "last_modification", value: "2019-12-16 11:36:02 +0000 (Mon, 16 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-06-26 09:21:08 +0200 (Tue, 26 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Microsoft Windows: BitLocker-protected operating system drives recovery (require AD backup)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "1;0" );
	script_xref( name: "URL", value: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250" );
	script_tag( name: "summary", value: "This policy setting allows you to control how BitLocker-protected
operating system drives are recovered in the absence of the required startup key information. This
policy setting is applied when you turn on BitLocker.

The 'Allow certificate-based data recovery agent' check box is used to specify whether a data
recovery agent can be used with BitLocker-protected operating system drives. Before a data recovery
agent can be used it must be added from the Public Key Policies item in either the Group Policy
Management Console or the Local Group Policy Editor. Consult the BitLocker Drive Encryption
Deployment Guide on Microsoft TechNet for more information about adding data recovery agents.

In 'Configure user storage of BitLocker recovery information' select whether users are allowed,
required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

Select 'Omit recovery options from the BitLocker setup wizard' to prevent users from specifying
recovery options when they turn on BitLocker on a drive. This means that you will not be able to
specify which recovery option to use when you turn on BitLocker, instead BitLocker recovery options
for the drive are determined by the policy setting.

In 'Save BitLocker recovery information to Active Directory Domain Services', choose which BitLocker
recovery information to store in AD DS for operating system drives. If you select 'Backup recovery
password and key package', both the BitLocker recovery password and key package are stored in AD DS.
Storing the key package supports recovering data from a drive that has been physically corrupted. If
you select 'Backup recovery password only, ' only the recovery password is stored in AD DS.

Select the 'Do not enable BitLocker until recovery information is stored in AD DS for operating
system drives' check box if you want to prevent users from enabling BitLocker unless the computer is
connected to the domain and the backup of BitLocker recovery information to AD DS succeeds.

Note: If the 'Do not enable BitLocker until recovery information is stored in AD DS for operating
system drives' check box is selected, a recovery password is automatically generated.

If you enable this policy setting, you can control the methods available to users to recover data
from BitLocker-protected operating system drives.

If this policy setting is disabled or not configured, the default recovery options are supported for
BitLocker recovery. By default a DRA is allowed, the recovery options can be specified by the user
including the recovery password and recovery key, and recovery information is not backed up to AD DS.

(C) Microsoft Corporation 2015." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Choose how BitLocker-protected operating system drives can be recovered";
solution = "Set following UI path accordingly:
Windows Components/BitLocker Drive Encryption/Operating System Drives/" + title;
type = "HKLM";
key = "Software\\Policies\\Microsoft\\FVE";
item = "OSRequireActiveDirectoryBackup";
reg_path = type + "\\" + key + "!" + item;
test_type = "RegKey";
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

