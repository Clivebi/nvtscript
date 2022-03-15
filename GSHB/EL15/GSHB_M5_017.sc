if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95052" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "IT-Grundschutz M5.017: Einsatz der Sicherheitsmechanismen von NFS" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_SSH_NFS.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.017: Einsatz der Sicherheitsmechanismen von NFS

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.017: Einsatz der Sicherheitsmechanismen von NFS\n";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
exports = get_kb_item( "GSHB/NFS/exports" );
dfstab = get_kb_item( "GSHB/NFS/dfstab" );
passwd = get_kb_item( "GSHB/NFS/passwd" );
fstab = get_kb_item( "GSHB/NFS/fstab" );
vfstab = get_kb_item( "GSHB/NFS/vfstab" );
lsexports = get_kb_item( "GSHB/NFS/lsexports" );
lsdfstab = get_kb_item( "GSHB/NFS/lsdfstab" );
lspasswd = get_kb_item( "GSHB/NFS/lspasswd" );
lsfstab = get_kb_item( "GSHB/NFS/lsfstab" );
lsvfstab = get_kb_item( "GSHB/NFS/lsvfstab" );
nfsd = get_kb_item( "GSHB/NFS/nfsd" );
mountd = get_kb_item( "GSHB/NFS/mountd" );
log = get_kb_item( "GSHB/NFS/log" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( exports == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( ContainsString( "error", exports ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein\nunbekannter Fehler auf, siehe Log Message!" );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
		else {
			if( nfsd == "false" && mountd == "false" && exports == "none" && dfstab == "none" && ( !IsMatchRegexp( fstab, ".*nfs.*" ) && !IsMatchRegexp( fstab, ".*:.*" ) ) && ( !IsMatchRegexp( vfstab, ".*nfs.*" ) && !IsMatchRegexp( vfstab, ".*:.*" ) ) ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Auf System wurden keine per NFS exportierten oder\nverbundenen Dateisysteme gefunden." );
			}
			else {
				if(fstab != "none"){
					Lst = split( buffer: fstab, keep: 0 );
					for(i = 0;i < max_index( Lst );i++){
						if(!IsMatchRegexp( Lst[i], ".*nfs.*" )){
							continue;
						}
						if(IsMatchRegexp( Lst[i], ".*nosuid.*" )){
							continue;
						}
						val1 += Lst[i] + "\n";
					}
				}
				if(vfstab != "none"){
					Lst = split( buffer: vfstab, keep: 0 );
					for(i = 0;i < max_index( Lst );i++){
						if(!IsMatchRegexp( Lst[i], ".*nfs.*" )){
							continue;
						}
						if(IsMatchRegexp( Lst[i], ".*nosuid.*" )){
							continue;
						}
						val2 += Lst[i] + "\n";
					}
				}
				if( val1 || val2 && ( nfsd == "false" && mountd == "false" ) ){
					cli_result = NASLString( "ne" );
					cli_desc = NASLString( "Beim Testen des Systems wurden folgende Fehler\ngefunden:\n\n" );
					if(val1){
						cli_desc += NASLString( "In der Datei /etc/fstab stehen folgende\nunzureichenden Einträge:\n" + val1 + "\n\n" );
					}
					if(val2){
						cli_desc += NASLString( "In der Datei /etc/vfstab stehen\nfolgende unzureichenden Einträge:\n" + val2 );
					}
				}
				else {
					if( val1 || val2 && ( nfsd != "false" && mountd != "false" ) ){
						cli_result = NASLString( "ne" );
						cli_desc = NASLString( "Beim Testen des Systems wurde festgestellt das das System als\nNFS Server und Client läuft. Außerdem wurden folgende Fehler\ngefunden:\n\n" );
						if(val1){
							cli_desc += NASLString( "In der Datei /etc/fstab stehen folgende\nunzureichenden Einträge:\n" + val1 + "\n\n" );
						}
						if(val2){
							cli_desc += NASLString( "In der Datei /etc/vfstab stehen folgende\nunzureichenden Einträge:\n" + val2 + "\n\n" );
						}
					}
					else {
						if( ( ( IsMatchRegexp( fstab, ".*nfs.*" ) && IsMatchRegexp( fstab, ".*:.*" ) ) || ( IsMatchRegexp( vfstab, ".*nfs.*" ) && IsMatchRegexp( vfstab, ".*:.*" ) ) ) && ( nfsd != "false" && mountd != "false" ) ){
							cli_result = NASLString( "ne" );
							cli_desc = NASLString( "Beim Testen des Systems wurde festgestellt das das System als\nNFS Server und Client läuft.\n\n" );
						}
						else {
							if(( ( !IsMatchRegexp( fstab, ".*nfs.*" ) && !IsMatchRegexp( fstab, ".*:.*" ) ) || ( !IsMatchRegexp( vfstab, ".*nfs.*" ) && !IsMatchRegexp( vfstab, ".*:.*" ) ) ) && ( nfsd == "false" && mountd == "false" )){
								cli_result = NASLString( "e" );
								if( fstab != "none" && vfstab != "none" ) {
									cli_desc = NASLString( "Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/fstab und /etc/vfstab festgestellt.\n\n" );
								}
								else {
									if( fstab != "none" && vfstab == "none" ) {
										cli_desc = NASLString( "Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/fstab festgestellt.\n\n" );
									}
									else {
										if(fstab == "none" && vfstab != "none"){
											cli_desc = NASLString( "Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/vfstab festgestellt.\n\n" );
										}
									}
								}
							}
						}
					}
				}
				if( exports == "ok" && ( nfsd == "true" && mountd == "true" ) ){
					serv_result = NASLString( "e" );
					serv_desc = NASLString( "Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/exports festgestellt.\n\n" );
				}
				else {
					if( ( exports == "ok" || exports == "none" ) && ( nfsd == "false" && mountd == "false" ) ){
						serv_result = NASLString( "e" );
						serv_desc = NASLString( "Beim Testen des Systems wurde festgestellt,\ndass kein NFS Server läuft.\n\n" );
					}
					else {
						if( exports != "none" && exports != "ok" && ( nfsd == "true" && mountd == "true" ) ){
							serv_result = NASLString( "ne" );
							serv_desc = NASLString( "Beim Testen des Systems wurden in der Konfigurationsdatei\n/etc/exports folgende Fehlerhafte Einträge gefunden:\n" + exports + "\n\n" );
						}
						else {
							if(exports == "none" && ( nfsd == "true" && mountd == "true" )){
								serv_result = NASLString( "ne" );
								serv_desc = NASLString( "Beim Testen des Systems wurde festgestellt, das der NFS\nServer läuft, aber die Konfigurationsdatei /etc/exports wurde\nnicht gefunden.\n\n" );
							}
						}
					}
				}
				if( dfstab != "none" && dfstab == "ok" ){
					serv_result = NASLString( "e" );
					serv_desc += NASLString( "Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/dfstab festgestellt.\n\n" );
				}
				else {
					if(dfstab != "none" && dfstab != "ok"){
						serv_result = NASLString( "ne" );
						serv_desc += NASLString( "Beim Testen des Systems wurden in der Konfigurationsdatei\n/etc/dfs/dfstab folgende Fehlerhafte Einträge gefunden:\n" + dfstab + "\n\n" );
					}
				}
				if( passwd == "no_nobody" && ( nfsd == "true" && mountd == "true" ) ){
					passwd_result = NASLString( "ne" );
					passwd_desc = NASLString( "Es sollte sichergestellt werden, dass ein Eintrag\nnobody:*:-2:-2:anonymous user:: in der /etc/passwd existiert\nund wirksam ist.\n\n" );
				}
				else {
					if( passwd == "nobody" && ( nfsd == "true" && mountd == "true" ) ){
						passwd_result = NASLString( "e" );
						passwd_desc = NASLString( "Es wurde festgestellt, dass ein Eintrag\nnobody:*:-2:-2:anonymous user:: in der /etc/passwd existiert.\n\n" );
					}
					else {
						passwd_result = NASLString( "e" );
					}
				}
				if(lsexports != "none" && !IsMatchRegexp( lsexports, "-rw-r--r--.*" )){
					lsexports_result = NASLString( "ne" );
					lsexports_desc = NASLString( "Die Zugriffrechte auf /etc/exports sollten immer 644 sein.\n\n" );
				}
				if(lsdfstab != "none" && !IsMatchRegexp( lsdfstab, "-rw-r--r--.*" )){
					lsdfstab_result = NASLString( "ne" );
					lsdfstab_desc = NASLString( "Die Zugriffrechte auf /etc/dfs/dfstab sollten immer 644 sein.\n\n" );
				}
				if(lspasswd != "none" && !IsMatchRegexp( lspasswd, "-rw-r--r--.*" )){
					lspasswd_result = NASLString( "ne" );
					lspasswd_desc = NASLString( "Die Zugriffrechte auf /etc/passwd sollten immer 644 sein.\n\n" );
				}
				if(lsfstab != "none" && !IsMatchRegexp( lsfstab, "-rw-r--r--.*" )){
					lsfstab_result = NASLString( "ne" );
					lsfstab_desc = NASLString( "Die Zugriffrechte auf /etc/fstab sollten immer 644 sein.\n\n" );
				}
				if(lsvfstab != "none" && !IsMatchRegexp( lsvfstab, "-rw-r--r--.*" )){
					lsvfstab_result = NASLString( "ne" );
					lsvfstab_desc = NASLString( "Die Zugriffrechte auf /etc/vfstab sollten immer 644 sein.\n\n" );
				}
			}
		}
	}
}
if( serv_result == "ne" || cli_result == "ne" || passwd_result == "ne" || lsexports_result == "ne" || lsdfstab_result == "ne" || lspasswd_result == "ne" || lsfstab_result == "ne" || lsvfstab_result == "ne" ){
	result = NASLString( "nicht erfüllt" );
	desc = cli_desc + serv_desc + passwd_desc + lsexports_desc + lsdfstab_desc + lspasswd_desc + lsfstab_desc + lsvfstab_desc;
}
else {
	if(serv_result == "e" && cli_result == "e" && passwd_result == "e" || ( serv_result == "e" && !cli_result ) && passwd_result == "e" || ( !serv_result && cli_result == "e" ) && passwd_result == "e"){
		result = NASLString( "erfüllt" );
		desc = serv_desc + cli_desc + passwd_desc;
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M5_017/result", value: result );
set_kb_item( name: "GSHB/M5_017/desc", value: desc );
set_kb_item( name: "GSHB/M5_017/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_017" );
}
exit( 0 );

