if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108078" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2017-02-10 10:55:08 +0100 (Fri, 10 Feb 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "AKIF Orientierungshilfe Windows 10: Ueberpruefungen" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "smb_reg_service_pack.sc", "lsc_options.sc" );
	script_mandatory_keys( "SMB/WindowsName" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://www.it-sicherheit.mpg.de/Orientierungshilfe_Windows10.pdf" );
	script_tag( name: "summary", value: "Diese Routine folgt der 'Orientierungshilfe zur datenarmen
  Konfiguration von Windows 10' des Arbeitskreis Informationssicherheit der deutschen
  Forschungseinrichtungen (AKIF) und ueberprueft das Host-System auf dessen Empfehlungen." );
	script_add_preference( name: "Orientierungshilfe Windows 10 Policies", type: "file", value: "" );
	script_tag( name: "qod", value: "98" );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(get_kb_item( "win/lsc/disable_win_cmd_exec" )){
	win_cmd_exec_disabled = TRUE;
}
func check_policy( check_desc, check_num, check_type, reg_key, reg_name, reg_type, reg_value, service_name, startup_type, wmi_username, wmi_password ){
	var check_desc, check_num, check_type, reg_key, reg_name, reg_type, reg_value, service_name;
	var startup_type, response, current_value, text_response, serQueryRes, cmd, extra;
	var wmi_username, wmi_password;
	if( ContainsString( check_type, "Registry" ) ){
		text_response = check_desc + "||" + check_num + "||" + check_type + "||" + reg_key + "||" + reg_name + "||" + reg_type + "||" + reg_value + "||";
		if(reg_key == "./."){
			return make_list( "unimplemented",
				 text_response + "Ueberpruefungs-Details in Policy Datei fehlen.\n" );
		}
		if( ContainsString( reg_key, "HKCU\\" ) ){
			reg_key = str_replace( string: reg_key, find: "HKCU\\", replace: "", count: 1 );
			type = "HKCU";
		}
		else {
			if( ContainsString( reg_key, "HKLM\\" ) ){
				reg_key = str_replace( string: reg_key, find: "HKLM\\", replace: "", count: 1 );
				type = "HKLM";
			}
			else {
				return make_list( "error",
					 text_response + "(fehlerhafte \"Reg-Key\" Details in Policy Datei).\n" );
			}
		}
		if(!registry_key_exists( key: reg_key, type: type )){
			return make_list( "failed",
				 text_response + "Registry-Key nicht vorhanden.\n" );
		}
		if( ContainsString( reg_type, "DWORD" ) ){
			current_value = registry_get_dword( key: reg_key, item: reg_name, type: type );
		}
		else {
			if( ContainsString( reg_type, "STRING" ) ){
				current_value = registry_get_sz( key: reg_key, item: reg_name, type: type );
			}
			else {
				return make_list( "error",
					 text_response + "Ueberpruefung fehlgeschlagen (fehlerhafte \"Reg-Type\" Details in Policy Datei).\n" );
			}
		}
		if( isnull( current_value ) ){
			return make_list( "failed",
				 text_response + "Registry-Name nicht vorhanden.\n" );
		}
		else {
			if( current_value == reg_value ){
				return make_list( "passed",
					 text_response + current_value + "\n" );
			}
			else {
				if( current_value != reg_value ){
					return make_list( "failed",
						 text_response + current_value + "\n" );
				}
				else {
					return make_list( "error",
						 text_response + "Ueberpruefung fehlgeschlagen.\n" );
				}
			}
		}
	}
	else {
		if( ContainsString( check_type, "Service" ) ){
			text_response = check_desc + "||" + check_num + "||" + check_type + "||" + service_name + "||" + startup_type + "||";
			if( defined_func( "win_cmd_exec" ) ){
				if(win_cmd_exec_disabled){
					return make_list( "error",
						 text_response + "Ueberpruefung fehlgeschlagen. Die Verwendung der benoetigten win_cmd_exec Funktion wurde in \"Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)\" manuell deaktiviert.\n" );
				}
				cmd = "cmd /c sc qc " + service_name;
				serQueryRes = win_cmd_exec( cmd: cmd, password: wmi_password, username: wmi_username );
				if( ContainsString( serQueryRes, "START_TYPE" ) ){
					if( ContainsString( serQueryRes, toupper( startup_type ) ) ){
						return make_list( "passed",
							 text_response + "Disabled\n" );
					}
					else {
						if( ContainsString( serQueryRes, "AUTO_START" ) && ContainsString( serQueryRes, "DELAYED" ) ){
							return make_list( "failed",
								 text_response + "Automatic (Delayed Start)\n" );
						}
						else {
							if( ContainsString( serQueryRes, "AUTO_START" ) ){
								return make_list( "failed",
									 text_response + "Automatic\n" );
							}
							else {
								if( ContainsString( serQueryRes, "DEMAND_START" ) ){
									return make_list( "failed",
										 text_response + "Manual\n" );
								}
								else {
									if(serQueryRes){
										extra = " Fehlermeldung: " + chomp( serQueryRes ) + ".";
									}
									return make_list( "error",
										 text_response + "Ueberpruefung fehlgeschlagen." + extra + "\n" );
								}
							}
						}
					}
				}
				else {
					if( ContainsString( serQueryRes, "Access is denied" ) ){
						return make_list( "error",
							 text_response + "Ueberpruefung fehlgeschlagen. Der Zugriff wurde verweigert.\n" );
					}
					else {
						if( ContainsString( serQueryRes, "The specified service does not exist as an installed service." ) ){
							return make_list( "error",
								 text_response + "Ueberpruefung fehlgeschlagen. Der Service existiert nicht.\n" );
						}
						else {
							if(serQueryRes){
								extra = " Fehlermeldung: " + chomp( serQueryRes ) + ".";
							}
							return make_list( "error",
								 text_response + "Ueberpruefung fehlgeschlagen." + extra + "\n" );
						}
					}
				}
			}
			else {
				return make_list( "error",
					 text_response + "Ueberpruefung fehlgeschlagen (keine WMI Unterstuetzung vorhanden).\n" );
			}
		}
		else {
			if( reg_key ){
				text_response = check_desc + "||" + check_num + "||" + check_type + "||" + reg_key + "||" + reg_name + "||" + reg_type + "||" + reg_value + "||";
			}
			else {
				text_response = check_desc + "||" + check_num + "||" + check_type + "||" + service_name + "||" + startup_type + "||";
			}
			return make_list( "error",
				 text_response + "Ueberpruefung fehlgeschlagen (fehlerhafte \"Ueberpruefung\" Details in Policy Datei).\n" );
		}
	}
}
if(!windows_name = get_kb_item( "SMB/WindowsName" )){
	exit( 0 );
}
policy_file = script_get_preference_file_content( "Orientierungshilfe Windows 10 Policies" );
if(!policy_file){
	exit( 0 );
}
policy_lines = split( buffer: policy_file, keep: FALSE );
max = max_index( policy_lines );
if(max < 5){
	set_kb_item( name: "policy/orientierungshilfe_win10/error", value: "Die Orientierungshilfe Windows 10 Policy Datei ist leer. Es koennen keine Ueberpruefungen durchgefuehrt werden." );
	exit( 0 );
}
if(!ContainsString( windows_name, "Windows 10" )){
	set_kb_item( name: "policy/orientierungshilfe_win10/error", value: "Es konnte kein Windows 10 erkannt werden (erkanntes OS: " + windows_name + "). Es koennen keine Ueberpruefungen durchgefuehrt werden." );
	exit( 0 );
}
if(ContainsString( windows_name, "LTSB" )){
	ltsb_version = TRUE;
}
wmi_username = kb_smb_login();
wmi_password = kb_smb_password();
wmi_domain = kb_smb_domain();
if(!wmi_username && !wmi_password){
	exit( 0 );
}
if(wmi_domain){
	wmi_username = wmi_domain + "/" + wmi_username;
}
for(i = 0;i < max;i++){
	if(policy_lines[i] == ""){
		continue;
	}
	entry = split( buffer: policy_lines[i], sep: ":", keep: FALSE );
	if( entry[0] == "Beschreibung" ){
		check_desc = entry[1];
	}
	else {
		if( entry[0] == "Nummerierung" ){
			check_num = entry[1];
		}
		else {
			if( entry[0] == "Ueberpruefung" ){
				check_type = entry[1];
			}
			else {
				if( entry[0] == "Reg-Key" ){
					reg_key = entry[1];
				}
				else {
					if( entry[0] == "Reg-Name" ){
						reg_name = entry[1];
					}
					else {
						if( entry[0] == "Reg-Type" ){
							reg_type = entry[1];
						}
						else {
							if( entry[0] == "Reg-Value" ){
								reg_value = entry[1];
							}
							else {
								if( entry[0] == "Service-Name" ){
									service_name = entry[1];
								}
								else {
									if( entry[0] == "Startup-Type" ){
										startup_type = entry[1];
									}
									else {
										if(entry[0] == "Servicing-Branch"){
											servicing_branch = entry[1];
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if(( i == max - 1 ) || ( policy_lines[i + 1] == "" )){
		if(( ltsb_version && ContainsString( servicing_branch, "LTSB" ) ) || ( !ltsb_version && ContainsString( servicing_branch, "CB" ) ) || ( !servicing_branch )){
			status = check_policy( check_desc: check_desc, check_num: check_num, check_type: check_type, reg_key: reg_key, reg_name: reg_name, reg_type: reg_type, reg_value: reg_value, service_name: service_name, startup_type: startup_type, wmi_username: wmi_username, wmi_password: wmi_password );
			if( status[0] == "passed" ){
				policy_pass += status[1] + "#-#";
			}
			else {
				if( status[0] == "failed" ){
					policy_fail += status[1] + "#-#";
				}
				else {
					if( status[0] == "unimplemented" ){
						policy_error += status[1] + "#-#";
					}
					else {
						if(status[0] == "error"){
							policy_error += status[1] + "#-#";
						}
					}
				}
			}
		}
		check_desc = NULL;
		check_num = NULL;
		check_type = NULL;
		reg_key = NULL;
		reg_name = NULL;
		reg_type = NULL;
		reg_value = NULL;
		service_name = NULL;
		startup_type = NULL;
		servicing_branch = NULL;
	}
}
if(policy_pass){
	set_kb_item( name: "policy/orientierungshilfe_win10/passed", value: policy_pass );
}
if(policy_fail){
	set_kb_item( name: "policy/orientierungshilfe_win10/failed", value: policy_fail );
}
if(policy_error){
	set_kb_item( name: "policy/orientierungshilfe_win10/error", value: policy_error );
}
exit( 0 );

