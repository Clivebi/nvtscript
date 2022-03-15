if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94248" );
	script_version( "$Revision: 12387 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.344: Überwachung von Windows-Systemen ab Windows Vista und Windows Server 2008" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04344.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_WMI_NtpServer.sc", "GSHB/GSHB_WMI_EventLogPolSet.sc", "GSHB/GSHB_WMI_PolSecSet.sc", "win_AdvancedPolicySettings.sc" );
	script_require_keys( "WMI/ELCP/GENERAL" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.344: Überwachung von Windows-Systemen ab Windows Vista und Windows Server 2008

  Stand: 15. Ergänzungslieferung (15. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.344: Überwachung von Windows-Systemen ab Windows Vista und Windows Server 2008\n";
require("http_func.inc.sc");
gshbm = "IT-Grundschutz M4.344: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
Domainrole = get_kb_item( "WMI/WMI_WindowsDomainrole" );
NtpServer = get_kb_item( "WMI/NtpServer" );
NtpServer = tolower( NtpServer );
domain = get_kb_item( "WMI/WMI_WindowsDomain" );
domain = tolower( domain );
if(!ContainsString( "none", NtpServer ) && !ContainsString( "error", NtpServer )){
	NtpServer = split( buffer: NtpServer, sep: ",", keep: 0 );
}
ELCP = get_kb_item( "WMI/ELCP/GENERAL" );
log = get_kb_item( "WMI/ELCP/GENERAL/log" );
if(ELCP == "ok" && Domainrole != "0"){
	AppEventLMaxSize = get_kb_item( "WMI/ELCP/AppEventLMaxSize" );
	SecEventLMaxSize = get_kb_item( "WMI/ELCP/SecEventLMaxSize" );
	SetEventLMaxSize = get_kb_item( "WMI/ELCP/SetEventLMaxSize" );
	SysEventLMaxSize = get_kb_item( "WMI/ELCP/SysEventLMaxSize" );
	AppEventLAutoBackupLogFiles = get_kb_item( "WMI/ELCP/AppEventLAutoBackupLogFiles" );
	SecEventLAutoBackupLogFiles = get_kb_item( "WMI/ELCP/SecEventLAutoBackupLogFiles" );
	SetEventLAutoBackupLogFiles = get_kb_item( "WMI/ELCP/SetEventLAutoBackupLogFiles" );
	SysEventLAutoBackupLogFiles = get_kb_item( "WMI/ELCP/SysEventLAutoBackupLogFiles" );
	AppEventLRetention = get_kb_item( "WMI/ELCP/AppEventLRetention" );
	SecEventLRetention = get_kb_item( "WMI/ELCP/SecEventLRetention" );
	SetEventLRetention = get_kb_item( "WMI/ELCP/SetEventLRetention" );
	SysEventLRetention = get_kb_item( "WMI/ELCP/SysEventLRetention" );
	AppEventLChannelAccess = get_kb_item( "WMI/ELCP/AppEventLChannelAccess" );
	SecEventLChannelAccess = get_kb_item( "WMI/ELCP/SecEventLChannelAccess" );
	SetEventLChannelAccess = get_kb_item( "WMI/ELCP/SetEventLChannelAccess" );
	SysEventLChannelAccess = get_kb_item( "WMI/ELCP/SysEventLChannelAccess" );
	SetEventLEnable = get_kb_item( "WMI/ELCP/SetEventLEnable" );
	CPSGENERAL = get_kb_item( "WMI/cps/GENERAL" );
	AuditAccountLogon = get_kb_item( "WMI/cps/AuditAccountLogon" );
	AuditAccountManage = get_kb_item( "WMI/cps/AuditAccountManage" );
	AuditPrivilegeUse = get_kb_item( "WMI/cps/AuditPrivilegeUse" );
	AuditObjectAccess = get_kb_item( "WMI/cps/AuditObjectAccess" );
	AuditPolicyChange = get_kb_item( "WMI/cps/AuditPolicyChange" );
	AuditLogonEvents = get_kb_item( "WMI/cps/AuditLogonEvents" );
	AuditSystemEvents = get_kb_item( "WMI/cps/AuditSystemEvents" );
	MaximumLogSizeApp = get_kb_item( "WMI/cps/MaximumLogSizeApp" );
	MaximumLogSizeEvent = get_kb_item( "WMI/cps/MaximumLogSizeEvent" );
	MaximumLogSizeSec = get_kb_item( "WMI/cps/MaximumLogSizeSec" );
	AuditRemovableStorage = get_kb_item( "WMI/AdvancedPolicy/RemovableStorage" );
	if(AuditAccountLogon != "None"){
		AuditAccountLogon = split( buffer: AuditAccountLogon, sep: "\n", keep: 0 );
		AuditAccountLogon = split( buffer: AuditAccountLogon[1], sep: "|", keep: 0 );
	}
	if(AuditAccountManage != "None"){
		AuditAccountManage = split( buffer: AuditAccountManage, sep: "\n", keep: 0 );
		AuditAccountManage = split( buffer: AuditAccountManage[1], sep: "|", keep: 0 );
	}
	if(AuditPrivilegeUse != "None"){
		AuditPrivilegeUse = split( buffer: AuditPrivilegeUse, sep: "\n", keep: 0 );
		AuditPrivilegeUse = split( buffer: AuditPrivilegeUse[1], sep: "|", keep: 0 );
	}
	if(AuditObjectAccess != "None"){
		AuditObjectAccess = split( buffer: AuditObjectAccess, sep: "\n", keep: 0 );
		AuditObjectAccess = split( buffer: AuditObjectAccess[1], sep: "|", keep: 0 );
	}
	if(AuditPolicyChange != "None"){
		AuditPolicyChange = split( buffer: AuditPolicyChange, sep: "\n", keep: 0 );
		AuditPolicyChange = split( buffer: AuditPolicyChange[1], sep: "|", keep: 0 );
	}
	if(AuditLogonEvents != "None"){
		AuditLogonEvents = split( buffer: AuditLogonEvents, sep: "\n", keep: 0 );
		AuditLogonEvents = split( buffer: AuditLogonEvents[1], sep: "|", keep: 0 );
	}
	if(AuditSystemEvents != "None"){
		AuditSystemEvents = split( buffer: AuditSystemEvents, sep: "\n", keep: 0 );
		AuditSystemEvents = split( buffer: AuditSystemEvents[1], sep: "|", keep: 0 );
	}
	if( AppEventLMaxSize == "None" && MaximumLogSizeApp == "None" ){
		MaximumLogSizeApp = "20480";
	}
	else {
		if( AppEventLMaxSize == "None" || !AppEventLMaxSize ){
			if(MaximumLogSizeApp != "None"){
				MaximumLogSizeApp = split( buffer: MaximumLogSizeApp, sep: "\n", keep: 0 );
				MaximumLogSizeApp = split( buffer: MaximumLogSizeApp[1], sep: "|", keep: 0 );
				MaximumLogSizeApp = MaximumLogSizeApp[2];
			}
		}
		else {
			if(AppEventLMaxSize != "0"){
				MaximumLogSizeApp = hex2dec( xvalue: AppEventLMaxSize );
			}
		}
	}
	if( SecEventLMaxSize == "None" && MaximumLogSizeSec == "None" ){
		MaximumLogSizeSec = "20480";
	}
	else {
		if( SecEventLMaxSize == "None" || !SecEventLMaxSize ){
			if(MaximumLogSizeSec != "None"){
				MaximumLogSizeSec = split( buffer: MaximumLogSizeSec, sep: "\n", keep: 0 );
				MaximumLogSizeSec = split( buffer: MaximumLogSizeSec[1], sep: "|", keep: 0 );
				MaximumLogSizeSec = MaximumLogSizeSec[2];
			}
		}
		else {
			if(SysEventLMaxSize != "0"){
				MaximumLogSizeSec = hex2dec( xvalue: SecEventLMaxSize );
			}
		}
	}
	if( SysEventLMaxSize == "None" && MaximumLogSizeEvent == "None" ){
		MaximumLogSizeEvent = "20480";
	}
	else {
		if( SysEventLMaxSize == "None" || !SysEventLMaxSize ){
			if(MaximumLogSizeEvent != "None"){
				MaximumLogSizeEvent = split( buffer: MaximumLogSizeEvent, sep: "\n", keep: 0 );
				MaximumLogSizeEvent = split( buffer: MaximumLogSizeEvent[1], sep: "|", keep: 0 );
				MaximumLogSizeEvent = MaximumLogSizeEvent[2];
			}
		}
		else {
			if(SysEventLMaxSize != "0"){
				MaximumLogSizeEvent = hex2dec( xvalue: SysEventLMaxSize );
			}
		}
	}
	if( SetEventLMaxSize != "0" && SetEventLMaxSize != "None" ) {
		MaximumLogSizeSetup = hex2dec( xvalue: SetEventLMaxSize );
	}
	else {
		if( SetEventLMaxSize == "None" ) {
			MaximumLogSizeSetup = "20480";
		}
		else {
			MaximumLogSizeSetup = SetEventLMaxSize;
		}
	}
	SeSecurityPrivilege = get_kb_item( "WMI/cps/SeSecurityPrivilege" );
	SeSecurityPrivilege = split( buffer: SeSecurityPrivilege, sep: "\n", keep: 0 );
	SeSecurityPrivilege = split( buffer: SeSecurityPrivilege[1], sep: "|", keep: 0 );
	for(i = 0;i < max_index( SeSecurityPrivilege );i++){
		if(SeSecurityPrivilege[i] == "1" || SeSecurityPrivilege[i] == "SeSecurityPrivilege"){
			continue;
		}
		SeSecurityPrivilegeUser += SeSecurityPrivilege[i] + ";";
	}
}
if(ELCP == "ok" && Domainrole == "0"){
	LocAppEventLMaxSize = get_kb_item( "WMI/ELCP/LocAppEventLMaxSize" );
	LocSecEventLMaxSize = get_kb_item( "WMI/ELCP/LocSecEventLMaxSize" );
	LocSysEventLMaxSize = get_kb_item( "WMI/ELCP/LocSysEventLMaxSize" );
	LocAppEventLRetention = get_kb_item( "WMI/ELCP/LocAppEventLRetention" );
	LocSecEventLRetention = get_kb_item( "WMI/ELCP/LocSecEventLRetention" );
	LocSysEventLRetention = get_kb_item( "WMI/ELCP/LocSysEventLRetention" );
	LocAppEventLRestrictGuestAccess = get_kb_item( "WMI/ELCP/LocAppEventLRestrictGuestAccess" );
	LocSecEventLRestrictGuestAccess = get_kb_item( "WMI/ELCP/LocSecEventLRestrictGuestAccess" );
	LocSysEventLRestrictGuestAccess = get_kb_item( "WMI/ELCP/LocSysEventLRestrictGuestAccess" );
	LocAppEventLAutoBackupLogFiles = get_kb_item( "WMI/ELCP/LocAppEventLAutoBackupLogFiles" );
	LocSecEventLAutoBackupLogFiles = get_kb_item( "WMI/ELCP/LocSecEventLAutoBackupLogFiles" );
	LocSysEventLAutoBackupLogFiles = get_kb_item( "WMI/ELCP/LocSysEventLAutoBackupLogFiles" );
	if(LocAppEventLMaxSize != "0" && LocAppEventLMaxSize != "None"){
		LocAppEventLMaxSize = hex2dec( xvalue: LocAppEventLMaxSize );
	}
	if(LocSecEventLMaxSize != "0" && LocSecEventLMaxSize != "None"){
		LocSecEventLMaxSize = hex2dec( xvalue: LocSecEventLMaxSize );
	}
	if(LocSysEventLMaxSize != "0" && LocSysEventLMaxSize != "None"){
		LocSysEventLMaxSize = hex2dec( xvalue: LocSysEventLMaxSize );
	}
	LocAppEventLMaxSize = LocAppEventLMaxSize / "1024";
	LocSecEventLMaxSize = LocSecEventLMaxSize / "1024";
	LocSysEventLMaxSize = LocSysEventLMaxSize / "1024";
}
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( ContainsString( "error", ELCP ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( !CPSGENERAL ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf.\\nEs konnte keine RSOP Abfrage durchgeführt werden." );
		}
		else {
			if( OSVER >= "6.0" ){
				if( Domainrole == "1" ){
					if( AuditAccountLogon[1] == "True" && AuditAccountLogon[3] == "True" && AuditLogonEvents[1] == "True" && AuditLogonEvents[3] == "True" && AuditPrivilegeUse[1] == "True" && AuditPolicyChange[1] == "True" && AuditPolicyChange[3] == "True" && AuditSystemEvents[1] == "True" && AuditSystemEvents[3] == "True" && AuditAccountManage[1] == "True" && AuditAccountManage[3] == "True" && AuditObjectAccess[1] == "True" && MaximumLogSizeApp >= 30080 && MaximumLogSizeEvent >= 30080 && MaximumLogSizeSec >= 100992 && MaximumLogSizeSetup < 30080 && ContainsString( NtpServer[0], domain ) && ( ( !IsMatchRegexp( AppEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) && !IsMatchRegexp( AppEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" ) ) || IsMatchRegexp( AppEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" ) ) && ( !IsMatchRegexp( SecEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) && !IsMatchRegexp( SecEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" ) ) && ( ( !IsMatchRegexp( SetEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) && !IsMatchRegexp( SetEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" ) ) || IsMatchRegexp( SetEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" ) ) && ( ( !IsMatchRegexp( SysEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) && !IsMatchRegexp( SysEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" ) ) || IsMatchRegexp( SysEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" ) ) && ( AuditRemovableStorage == "None" || AuditRemovableStorage == "Success and Failure" ) ){
						result = NASLString( "erfüllt" );
						desc = NASLString( "Soweit konfigurierbar, entspricht das System der\nIT-Grundschutz Maßnahme M4.344." );
					}
					else {
						result = NASLString( "nicht erfüllt" );
						if( ContainsString( "None", AuditAccountLogon ) ) {
							val += "\n" + "Anmeldeversuche überwachen: " + AuditAccountLogon;
						}
						else {
							if(AuditAccountLogon[1] != "True"){
								val += "\n" + "Anmeldeversuche überwachen Fehlgeschlagen: " + AuditAccountLogon[1];
							}
							if(AuditAccountLogon[3] != "True"){
								val += "\n" + "Anmeldeversuche überwachen Erfolgreich: " + AuditAccountLogon[3];
							}
						}
						if( ContainsString( "None", AuditAccountManage ) ) {
							val += "\n" + "Kontenverwaltung überwachen: " + AuditAccountManage;
						}
						else {
							if(AuditAccountManage[1] != "True"){
								val += "\n" + "Kontenverwaltung überwachen Fehlgeschlagen: " + AuditAccountManage[1];
							}
							if(AuditAccountManage[3] != "True"){
								val += "\n" + "Kontenverwaltung überwachen Erfolgreich: " + AuditAccountManage[3];
							}
						}
						if( ContainsString( "None", AuditLogonEvents ) ) {
							val += "\n" + "Anmeldeereignisse überwachen: " + AuditLogonEvents;
						}
						else {
							if(AuditLogonEvents[1] != "True"){
								val += "\n" + "Anmeldeereignisse überwachen Fehlgeschlagen: " + AuditLogonEvents[1];
							}
							if(AuditLogonEvents[3] != "True"){
								val += "\n" + "Anmeldeereignisse überwachen Erfolgreich: " + AuditLogonEvents[3];
							}
						}
						if( ContainsString( "None", AuditObjectAccess ) ) {
							val += "\n" + "Objektzugriffsversuche überwachen: " + AuditObjectAccess;
						}
						else {
							if(AuditObjectAccess[1] != "True"){
								val += "\n" + "Objektzugriffsversuche überwachen: " + AuditObjectAccess[1];
							}
						}
						if( ContainsString( "None", AuditPolicyChange ) ) {
							val += "\n" + "Richtlinienänderungen überwachen: " + AuditPolicyChange;
						}
						else {
							if(AuditPolicyChange[1] != "True"){
								val += "\n" + "Richtlinienänderungen überwachen Fehlgeschlagen: " + AuditPolicyChange[1];
							}
							if(AuditPolicyChange[3] != "True"){
								val += "\n" + "Richtlinienänderungen überwachen Erfolgreich: " + AuditPolicyChange[3];
							}
						}
						if( ContainsString( "None", AuditPrivilegeUse ) ) {
							val += "\n" + "Rechteverwendung überwachen: " + AuditPrivilegeUse;
						}
						else {
							if(AuditPrivilegeUse[1] != "True"){
								val += "\n" + "Rechteverwendung überwachen: " + AuditPrivilegeUse[1];
							}
						}
						if( ContainsString( "None", AuditSystemEvents ) ) {
							val += "\n" + "Systemereignisse überwachen: " + AuditSystemEvents;
						}
						else {
							if(AuditSystemEvents[1] != "True"){
								val += "\n" + "Systemereignisse überwachen Fehlgeschlagen: " + AuditSystemEvents[1];
							}
							if(AuditSystemEvents[3] != "True"){
								val += "\n" + "Systemereignisse überwachen Erfolgreich: " + AuditSystemEvents[3];
							}
						}
						if(SetEventLEnable == "0"){
							val += "\n" + "Der Setup-Protokolldienst ist nicht aktiviert";
						}
						if(MaximumLogSizeApp < 30080){
							val += "\n" + "Maximale Größe des Anwendungsprotokolls: " + MaximumLogSizeApp + " Kilobyte";
						}
						if(MaximumLogSizeEvent < 30080){
							val += "\n" + "Maximale Größe des Systemprotokolls: " + MaximumLogSizeEvent + " Kilobyte";
						}
						if(MaximumLogSizeSec < 100992){
							val += "\n" + "Maximale Größe des Sicherheitsprotokolls: " + MaximumLogSizeSec + " Kilobyte";
						}
						if(MaximumLogSizeSetup < 30080){
							val += "\n" + "Maximale Größe des Setupprotokolls: " + MaximumLogSizeSetup + " Kilobyte";
						}
						if(AppEventLAutoBackupLogFiles != 1){
							val += "\n" + "Für den Anwendungs-Protokolldienst, ist die Richtlinie\\n-Volles Protokoll automatisch sichern- nicht aktiviert";
						}
						if(SecEventLAutoBackupLogFiles != 1){
							val += "\n" + "Für den Sicherheits-Protokolldienst, ist die Richt-\\nlinie -Volles Protokoll automatisch sichern-\\nnicht aktiviert";
						}
						if(SetEventLAutoBackupLogFiles != 1){
							val += "\n" + "Für den Setup-Protokolldienst, ist die Richtlinie\\n-Volles Protokoll automatisch sichern- nicht aktiviert";
						}
						if(SysEventLAutoBackupLogFiles != 1){
							val += "\n" + "Für den System-Protokolldienst, ist die Richtlinie\\n-Volles Protokoll automatisch sichern- nicht aktiviert";
						}
						if(AppEventLRetention != 1){
							val += "\n" + "Für den Anwendungs-Protokolldienst, ist die Richtlinie\\n-Alte Ereignisse beibehalten- nicht aktiviert";
						}
						if(SecEventLRetention != 1){
							val += "\n" + "Für den Sicherheits-Protokolldienst, ist die Richt-\\nlinie -Alte Ereignisse beibehalten- nicht aktiviert";
						}
						if(SetEventLRetention != 1){
							val += "\n" + "Für den Setup-Protokolldienst, ist die Richtlinie\\n-Alte Ereignisse beibehalten- nicht aktiviert";
						}
						if(SysEventLRetention != 1){
							val += "\n" + "Für den System-Protokolldienst, ist die Richtlinie\\n-Alte Ereignisse beibehalten- nicht aktiviert";
						}
						if(IsMatchRegexp( AppEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) || IsMatchRegexp( AppEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" ) || !IsMatchRegexp( AppEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" )){
							if(!IsMatchRegexp( AppEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" )){
								val += "\n" + "Auf das Anwendungsprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, den -Built-in guests- der Zugriff\\nnicht verweigert";
							}
							if(IsMatchRegexp( AppEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" )){
								val += "\n" + "Auf das Anwendungsprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, den -Built-in guests-\\nZugriff gewährt";
							}
							if(IsMatchRegexp( AppEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" )){
								val += "\n" + "Auf das Anwendungsprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, -Anonymous logon- Zugriff gewährt";
							}
						}
						if(IsMatchRegexp( SecEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) || IsMatchRegexp( SecEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" )){
							if(IsMatchRegexp( SecEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" )){
								val += "\n" + "Auf das Sicherheitsprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, den -Built-in guests-\\nZugriff gewährt";
							}
							if(IsMatchRegexp( SecEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" )){
								val += "\n" + "Auf das Sicherheitsprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, -Anonymous logon- Zugriff gewährt";
							}
						}
						if(IsMatchRegexp( SetEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) || IsMatchRegexp( SetEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" ) || !IsMatchRegexp( SetEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" )){
							if(!IsMatchRegexp( SetEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" )){
								val += "\n" + "Auf das Setupprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, den -Built-in guests- der Zugriff\\nnicht verweigert";
							}
							if(IsMatchRegexp( SetEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" )){
								val += "\n" + "Auf das Setupprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, den -Built-in guests-\\nZugriff gewährt";
							}
							if(IsMatchRegexp( SetEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" )){
								val += "\n" + "Auf das Setupprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, -Anonymous logon- Zugriff gewährt";
							}
						}
						if(IsMatchRegexp( SysEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" ) || IsMatchRegexp( SysEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" ) || !IsMatchRegexp( SysEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" )){
							if(!IsMatchRegexp( SysEventLChannelAccess, "\\(D;;0x.*;;;BG\\)" )){
								val += "\n" + "Auf das Systemprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, den -Built-in guests-\\nder Zugriff nicht verweigert";
							}
							if(IsMatchRegexp( SysEventLChannelAccess, "\\(A;;0x.*;;;BG\\)" )){
								val += "\n" + "Auf das Systemprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, den -Built-in guests-\\nZugriff gewährt";
							}
							if(IsMatchRegexp( SysEventLChannelAccess, "\\(A;;0x.*;;;AN\\)" )){
								val += "\n" + "Auf das Systemprotokoll wurde mit der Richtlinie\\n-Protokollzugriff-, -Anonymous logon- Zugriff gewährt";
							}
						}
						if(!ContainsString( NtpServer[0], domain )){
							val += "\n" + "Auf dem System wurde NTP-Server hinterlegt, der nicht\\naus der lokalen Domain stammt: " + NtpServer[0];
						}
						if(AuditRemovableStorage != "None" || AuditRemovableStorage != "Success and Failure"){
							val += "\n" + "Der Zugriff auf Wechselmedien sollte überwacht werden (ab Windows 7 über \"Erweiterte Überwachungsrichtlinienkonfiguration\" aktivierbar).";
						}
						desc = NASLString( "\nDas System entspricht nicht dem konfigurierbaren Teil\nder IT-Grundschutz Maßnahme M4.344.\n" + val );
					}
				}
				else {
					if( LocAppEventLMaxSize >= 30080 && LocSysEventLMaxSize >= 30080 && LocSecEventLMaxSize >= 100992 && LocAppEventLRetention == "FFFFFFFF" && LocSecEventLRetention == "FFFFFFFF" && LocSysEventLRetention == "FFFFFFFF" && LocAppEventLRestrictGuestAccess == "1" && LocSecEventLRestrictGuestAccess == "1" && LocSysEventLRestrictGuestAccess == "1" && LocAppEventLAutoBackupLogFiles == "1" && LocSecEventLAutoBackupLogFiles == "1" && LocSysEventLAutoBackupLogFiles == "1" ){
						result = NASLString( "unvollständig" );
						desc = NASLString( "Das System ist kein Domainmitglied und deshalb kann\nnicht alles überprüft werden.\nDie Einstellungen für\nEventlog - Größe, - Aufbewahrung, - Archivierung und\ndie Einschränkungen für den Gastzugriff sind richtig \nkonfiguriert." );
					}
					else {
						if(LocAppEventLMaxSize < 30080){
							val += "\n" + "Maximale Größe des Anwendungsprotokolls: " + LocAppEventLMaxSize + " Kilobyte";
						}
						if(LocSysEventLMaxSize < 30080){
							val += "\n" + "Maximale Größe des Systemprotokolls: " + LocSysEventLMaxSize + " Kilobyte";
						}
						if(LocSecEventLMaxSize < 100992){
							val += "\n" + "Maximale Größe des Sicherheitsprotokolls: " + LocSecEventLMaxSize + " Kilobyte";
						}
						if(LocAppEventLAutoBackupLogFiles != 1 && LocAppEventLRetention != "FFFFFFFF"){
							val += "\n" + "Für den Anwendungs-Protokolldienst wurde die\\nEinstellung 'Volles Protokoll archivieren, Ereignisse\\nüberschreiben- nicht aktiviert";
						}
						if(LocSecEventLAutoBackupLogFiles != 1 && LocSecEventLRetention != "FFFFFFFF"){
							val += "\n" + "Für den Sicherheits-Protokolldienst wurde die\\nEinstellung 'Volles Protokoll archivieren, Ereignisse\\nüberschreiben- nicht aktiviert";
						}
						if(LocSysEventLAutoBackupLogFiles != 1 && LocSysEventLRetention != "FFFFFFFF"){
							val += "\n" + "Für den System-Protokolldienst wurde die Einstellung\\n'Volles Protokoll archivieren, Ereignisse\\nüberschreiben- nicht aktiviert";
						}
						if(LocAppEventLRestrictGuestAccess != "1"){
							val += "\n" + "Für den Anwendungs-Protokolldienst wurde die Ein-\\nstellung -RestrictGuestAccess- in der Registry\\nauf '0' gesetzt";
						}
						if(LocSecEventLRestrictGuestAccess != "1"){
							val += "\n" + "Für den Sicherheits-Protokolldienst wurde die\\nEinstellung -RestrictGuestAccess- in der Registry\\nauf '0' gesetzt";
						}
						if(LocSysEventLRestrictGuestAccess != "1"){
							val += "\n" + "Für den System-Protokolldienst wurde die Einstellung\\n-RestrictGuestAccess- in der Registry auf '0' gesetzt";
						}
						result = NASLString( "unvollständig" );
						desc = NASLString( "Das System ist kein Domainmitglied und deshalb kann\nnicht alles überprüft werden.\nFolgende Einstellungen\nsind nicht richtig konfiguriert:" + val );
					}
				}
			}
			else {
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Das System ist kein Microsoft Windows System größer gleich Windows Vista." );
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_344/result", value: result );
set_kb_item( name: "GSHB/M4_344/desc", value: desc );
set_kb_item( name: "GSHB/M4_344/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_344" );
}
exit( 0 );

