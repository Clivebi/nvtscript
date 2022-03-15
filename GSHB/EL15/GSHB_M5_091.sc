if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95070" );
	script_version( "$Revision: 10625 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:24:35 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M5.091: Einsatz von Personal Firewalls für Clients" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05091.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_WMI_WinFirewallStat.sc", "GSHB/GSHB_SSH_iptables.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.091: Einsatz von Personal Firewalls für Clients.

Stand: 14. Ergänzungslieferung (14. EL).

Hinweis:
Getestet wird auf die Microsoft Windows Firewall. Für Vista und Windows 7
auf jegliche Firewall die sich systemkonform installiert.
Auf Linux, soweit möglich, anzeige der iptables Regeln." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.091: Einsatz von Personal Firewalls für Clients\n";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
Domainrole = get_kb_item( "WMI/WMI_WindowsDomainrole" );
SMBOSVER = get_kb_item( "SMB/WindowsVersion" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
FW = get_kb_item( "WMI/WinFirewall" );
IPFilter = get_kb_item( "WMI/WinFirewall/IPFilter" );
STD = get_kb_item( "WMI/WinFirewall/STD" );
DOM = get_kb_item( "WMI/WinFirewall/DOM" );
PUB = get_kb_item( "WMI/WinFirewall/PUB" );
Firewall_Name = get_kb_item( "WMI/WinFirewall/Firewall_Name" );
Firewall_State = get_kb_item( "WMI/WinFirewall/Firewall_State" );
log = get_kb_item( "WMI/WinFirewall/log" );
ruleset = get_kb_item( "GSHB/iptables/ruleset" );
targets = get_kb_item( "GSHB/iptables/targets" );
names = get_kb_item( "GSHB/iptables/names" );
matches = get_kb_item( "GSHB/iptables/matches" );
iptableslog = get_kb_item( "GSHB/iptables/log" );
uname = get_kb_item( "GSHB/iptables/uname" );
sunipfilter = get_kb_item( "GSHB/iptables/ipfilter" );
sunipfilterstat = get_kb_item( "GSHB/iptables/ipfilterstat" );
gshbm = "GSHB Maßnahme 5.091: ";
if( OSVER != "none" ){
	if( FW == "error" ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( OSVER < "5.1" ){
			result = NASLString( "unvollständig" );
			desc = NASLString( "Das Windows 2000 System kann nicht geprüft werden." );
		}
		else {
			if( FW == "on" ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Auf dem System ist eine Personal Firewall aktiviert." );
			}
			else {
				if( OSVER == "5.2" && OSTYPE != "none" && OSTYPE > 1 ){
					IPFilter = split( buffer: IPFilter, sep: "\n", keep: 0 );
					IPFilter = split( buffer: IPFilter[1], sep: "|", keep: 0 );
					NWCard = IPFilter[0];
					IPFilter = IPFilter[2];
					if( IPFilter == "True" ){
						result = NASLString( "erfüllt" );
						desc = NASLString( "Auf dem System ist die Windows Firewall für folgende\\nNetzwerkkarte aktiviert:\\n" + NWCard );
					}
					else {
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Auf dem System ist keine Personal Firewall aktiviert." );
					}
				}
				else {
					if( Firewall_State != "none" && Firewall_State != "inapplicable" ){
						Firewall_Name = split( buffer: Firewall_Name, sep: "\n", keep: 0 );
						Firewall_Name = split( buffer: Firewall_Name[1], sep: "|", keep: 0 );
						Firewall_Name = Firewall_Name[0];
						Firewall_State = split( buffer: Firewall_State, sep: "\n", keep: 0 );
						Firewall_State = split( buffer: Firewall_State[1], sep: "|", keep: 0 );
						Firewall_State = Firewall_State[1];
						if( Firewall_State == "266256" ){
							result = NASLString( "erfüllt" );
							desc = NASLString( "Auf dem System ist folgende Firewall Software aktiviert:\\n" + Firewall_Name );
						}
						else {
							if( Firewall_State == "262160" && Domainrole == "0" && STD == "1" ){
								result = NASLString( "erfüllt" );
								desc = NASLString( "Auf dem System ist die Windows Firewall aktiviert." );
							}
							else {
								if( Firewall_State == "262160" && Domainrole == "0" && STD == "off" ){
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Auf dem System ist keine Personal Firewall aktiviert." );
								}
								else {
									if( Firewall_State == "262160" && Domainrole == "1" && DOM == "1" ){
										result = NASLString( "erfüllt" );
										desc = NASLString( "Auf dem System ist die Windows Firewall aktiviert." );
									}
									else {
										if(Firewall_State == "262160" && Domainrole == "1" && DOM == "off"){
											result = NASLString( "nicht erfüllt" );
											desc = NASLString( "Auf dem System ist keine Personal Firewall aktiviert." );
										}
									}
								}
							}
						}
					}
					else {
						if( Domainrole == "0" || Domainrole == "2" ){
							if( STD == "off" && PUB == "off" ){
								result = NASLString( "nicht erfüllt" );
								desc = NASLString( "Auf dem System ist keine Personal Firewall aktiviert." );
							}
							else {
								if( STD == "1" && PUB == "1" ){
									result = NASLString( "erfüllt" );
									desc = NASLString( "Auf dem System ist die Windows Firewall aktiviert." );
								}
								else {
									if( STD == "off" && PUB == "1" ){
										result = NASLString( "unvollständig" );
										desc = NASLString( "\\nAuf dem System ist die Windows Firewall nur für\\n-Öffentliche Netzwerke- aktiviert. Sie sollten die Windows\\nFirewall für sämtliche Netzwerke aktivieren." );
									}
									else {
										if(STD == "1" && PUB == "off"){
											result = NASLString( "unvollständig" );
											desc = NASLString( "\\nAuf dem System ist die Windows Firewall nur für\\n-Private- / Arbeitsplatz Netzwerke- aktiviert. Sie sollten die\\nWindows Firewall für sämtliche Netzwerke aktivieren." );
										}
									}
								}
							}
						}
						else {
							if(Domainrole == "1" || Domainrole > 2){
								if( DOM == "off" ){
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Auf dem System ist keine Personal Firewall aktiviert." );
								}
								else {
									if(DOM == "1"){
										result = NASLString( "erfüllt" );
										desc = NASLString( "Auf dem System ist die Windows Firewall aktiviert." );
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
else {
	if( ruleset == "windows" ){
		result = NASLString( "Fehler" );
		if( !ContainsString( "none", OSNAME ) && !ContainsString( "error", OSNAME ) ) {
			desc = NASLString( "\nFolgendes System wurde erkannt:\n" + OSNAME + "\nAllerdings konnte auf das System nicht korrekt zugegriffen\nwerden. Folgende Fehler sind aufgetreten:\n" + log );
		}
		else {
			desc = NASLString( "\nDas System scheint ein Windows-System zu sein. Allerdings\nkonnte auf das System nicht korrekt zugegriffen werden.\nFolgende Fehler sind aufgetreten:\n" + log );
		}
	}
	else {
		if( IsMatchRegexp( uname, "SunOS.*" ) ){
			if( sunipfilter == "noperm" || sunipfilterstat == "noperm" ){
				result = NASLString( "Fehler" );
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
				if(sunipfilter == "noperm"){
					desc += NASLString( "\nSie haben nicht die Berechtigung um den Befehl\n\"ipf -V\" auszuführen." );
				}
				if(sunipfilterstat == "noperm"){
					desc += NASLString( "\nSie haben nicht die Berechtigung um den Befehl\n\"ipfstat -io\" auszuführen." );
				}
			}
			else {
				if( sunipfilter == "notfound" || sunipfilterstat == "notfound" ){
					result = NASLString( "Fehler" );
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
					if(sunipfilter == "notfound"){
						desc += NASLString( "\nDer Befehl \"ipf -V\" konnte nicht gefunden, bzw ausgeführt\nwerden." );
					}
					if(sunipfilterstat == "notfound"){
						desc += NASLString( "\nDer Befehl \"ipfstat -io\" konnte nicht gefunden, bzw ausgeführt\nwerden." );
					}
				}
				else {
					if( sunipfilter == "off" ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Eine Abfrage mit ipf -V hat ergeben, dass keine IP Filter\nlaufen." );
					}
					else {
						if( sunipfilter == "on" ){
							if( sunipfilterstat == "nofilter" ){
								result = NASLString( "nicht erfüllt" );
								desc = NASLString( "Beim Aufruf des Befehls ipfstat -io wurden keine IP Filter\nzurückgegeben." );
							}
							else {
								result = NASLString( "unvollständig" );
								desc = NASLString( "Bitte überprüfen Sie das iptables ruleset:\n" + sunipfilterstat );
							}
						}
						else {
							if(sunipfilter != "off" && sunipfilter != "on"){
								result = NASLString( "Fehler" );
								if(!iptableslog){
									desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
								}
								if(iptableslog){
									desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
								}
							}
						}
					}
				}
			}
		}
		else {
			if( ruleset == "error" ){
				result = NASLString( "Fehler" );
				if(!iptableslog){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
				}
				if(iptableslog){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
				}
			}
			else {
				if( ( ruleset == "notfound" || ruleset == "noperm" ) && ( ( !ContainsString( targets, "notfound" ) && !ContainsString( targets, "none" ) ) && ( !ContainsString( names, "notfound" ) && !ContainsString( names, "none" ) ) && ( !ContainsString( matches, "notfound" ) && !ContainsString( matches, "none" ) ) ) ){
					result = NASLString( "unvollständig" );
					if( ruleset == "notfound" ) {
						desc = NASLString( "Der Befehl iptables konnte nicht gefunden werden.\\nWahrscheinlich reicht die Berechtigung nicht aus." );
					}
					else {
						if(ruleset == "noperm"){
							desc = NASLString( "Der Befehl iptables konnte nicht ausgeführt werden, da die\\nBerechtigung nicht ausreicht." );
						}
					}
					desc += NASLString( "\nFolgende iptables Module wurden im proc Filesystem gefunden:\n" + targets + names + matches + "\nBitte überprüfen Sie die iptable rules manuell." );
				}
				else {
					if( ruleset == "notfound" || ruleset == "noperm" && ( ( "notfound" == targets || "none" == targets ) && ( "notfound" == names || "none" == names ) && ( "notfound" == matches || "none" == matches ) ) ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Es war nicht möglich den Befehl iptabels auszuführen und es\nwurden keine iptables Module im proc Filesystem gefunden." );
					}
					else {
						result = NASLString( "unvollständig" );
						desc = NASLString( "Bitte überprüfen Sie das iptables ruleset:\n" + ruleset );
					}
				}
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M5_091/result", value: result );
set_kb_item( name: "GSHB/M5_091/desc", value: desc );
set_kb_item( name: "GSHB/M5_091/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_091" );
}
exit( 0 );

