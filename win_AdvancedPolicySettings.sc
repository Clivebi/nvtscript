if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109001" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2017-06-23 12:03:14 +0200 (Fri, 23 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Read all Windows Policy Security Settings (Windows)" );
	script_family( "Policy" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc", "lsc_options.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_tag( name: "summary", value: "Read all Windows Advanced Policy Security Settings (Windows).

Note: This script saves into DB only and does not report any output." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!policy_verify_win_ver( min_ver: "6.1" )){
	policy_logging( text: "Host is not at least a Microsoft Windows 7 system. Older versions of
Windows are not supported any more. Please update the Operating System.", error: TRUE );
}
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "/" + usrname;
}
passwd = kb_smb_password();
if(get_kb_item( "win/lsc/disable_win_cmd_exec" )){
	policy_logging( text: "Error: Usage of win_cmd_exec required for this check was disabled manually
within \"Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)\".", error: TRUE );
	exit( 0 );
}
AdvancedPolicy = win_cmd_exec( cmd: "auditpol /get /category:*", password: passwd, username: usrname );
pnpaudit = win_cmd_exec( cmd: "auditpol /get /subcategory:`Plug and Play Events`", password: passwd, username: usrname );
if(!AdvancedPolicy || ContainsString( tolower( AdvancedPolicy ), "smb sessionerror" )){
	policy_logging( text: "Error: Could not query the audit policy.", error: TRUE );
	exit( 0 );
}
AdvancedPolicy = split( buffer: AdvancedPolicy, keep: FALSE );
for pol in AdvancedPolicy {
	name = eregmatch( string: pol, pattern: "^\\s+(.*)\\s{2,}(Success and Failure|Success|Failure|No Auditing)" );
	if(chomp( name )){
		if(ContainsString( name[1], "/" )){
			name[1] = str_replace( string: name[1], find: "/", replace: "" );
		}
		key = "WMI/AdvancedPolicy/" + str_replace( string: name[1], find: " ", replace: "" );
		value = name[2];
		set_kb_item( name: key, value: value );
	}
}
pnpaudit = split( buffer: pnpaudit, keep: FALSE );
for pol in pnpaudit {
	name = eregmatch( string: pol, pattern: "^\\s+(.*)\\s{2,}(Success and Failure|Success|Failure|No Auditing)" );
	if(chomp( name )){
		if(ContainsString( name[1], "/" )){
			name[1] = str_replace( string: name[1], find: "/", replace: "" );
		}
		key = "WMI/AdvancedPolicy/" + str_replace( string: name[1], find: " ", replace: "" );
		value = name[2];
		set_kb_item( name: key, value: value );
	}
}
exit( 0 );

