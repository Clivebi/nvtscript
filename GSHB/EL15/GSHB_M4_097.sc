if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94212" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.097: Ein Dienst pro Server (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "secpod_open_tcp_ports.sc" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04097.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.097: Ein Dienst pro Server.

  Stand: 14. Erg�nzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("itg.inc.sc");
require("wmi_svc.inc.sc");
require("wmi_user.inc.sc");
require("wmi_misc.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M4.097: Ein Dienst pro Server\n";
gshbm = "IT-Grundschutz M4.097: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
log = get_kb_item( "WMI/WMI_OS/log" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
if(host && usrname && passwd){
	handle = wmi_connect( host: host, username: usrname, password: passwd );
	vhdsvc = wmi_svc_prop( handle: handle, svcName: "vhdsvc" );
	nvspwmi = wmi_svc_prop( handle: handle, svcName: "nvspwmi" );
	vmms = wmi_svc_prop( handle: handle, svcName: "vmms" );
	if(vhdsvc){
		val = split( buffer: vhdsvc, sep:"\\n", keep: 0 );
		for(i = 1;i < max_index( val );i++){
			if( ContainsString( val[i], "Caption =" ) ) {
				vhdsvc_cap = val[i] - "Caption = ";
			}
			else {
				if( ContainsString( val[i], "Started =" ) ) {
					vhdsvc_started = val[i] - "Started = ";
				}
				else {
					if( ContainsString( val[i], "StartMode =" ) ) {
						vhdsvc_startmode = val[i] - "StartMode = ";
					}
					else {
						if(ContainsString( val[i], "State =" )){
							vhdsvc_state = val[i] - "State = ";
						}
					}
				}
			}
		}
	}
	if(nvspwmi){
		val = split( buffer: nvspwmi, sep:"\\n", keep: 0 );
		for(i = 1;i < max_index( val );i++){
			if( ContainsString( val[i], "Caption =" ) ) {
				nvspwmi_cap = val[i] - "Caption = ";
			}
			else {
				if( ContainsString( val[i], "Started =" ) ) {
					nvspwmi_started = val[i] - "Started = ";
				}
				else {
					if( ContainsString( val[i], "StartMode =" ) ) {
						nvspwmi_startmode = val[i] - "StartMode = ";
					}
					else {
						if(ContainsString( val[i], "State =" )){
							nvspwmi_state = val[i] - "State = ";
						}
					}
				}
			}
		}
	}
	if(vmms){
		val = split( buffer: vmms, sep:"\\n", keep: 0 );
		for(i = 1;i < max_index( val );i++){
			if( ContainsString( val[i], "Caption =" ) ) {
				vmms_cap = val[i] - "Caption = ";
			}
			else {
				if( ContainsString( val[i], "Started =" ) ) {
					vmms_started = val[i] - "Started = ";
				}
				else {
					if( ContainsString( val[i], "StartMode =" ) ) {
						vmms_startmode = val[i] - "StartMode = ";
					}
					else {
						if(ContainsString( val[i], "State =" )){
							vmms_state = val[i] - "State = ";
						}
					}
				}
			}
		}
	}
}
ports = tcp_get_all_ports();
portchecklist = make_list( "21",
	 "22",
	 "23",
	 "25",
	 "42",
	 "53",
	 "66",
	 "80",
	 "102",
	 "109",
	 "110",
	 "115",
	 "118",
	 "119",
	 "143",
	 "270",
	 "465",
	 "515",
	 "548",
	 "554",
	 "563",
	 "992",
	 "993",
	 "995",
	 "1270",
	 "1433",
	 "1434",
	 "1723",
	 "1755",
	 "2393",
	 "2394",
	 "2725",
	 "8080",
	 "51515" );
PORTTITEL = "
21 = File Transfer Protocol (FTP)
22 = Secure Shell (SSH) Protocol
23 = Telnet
25 = Simple Mail Transfer (SMTP)
42 = Windows Internet Name Service (WINS)
53 = DNS Server
66 = Oracle SQL*NET
80 = World Wide Web (HTTP)
102 = Microsoft Exchange MTA Stacks (X.400)
109 = Post Office Protocol - Version 2 (POP2)
110 = Post Office Protocol - Version 3 (POP3)
115 = Simple File Transfer Protocol (SFTP)
118 = SQL Services
119 = Network News Transfer Protocol (NNTP)
143 = Internet Message Access Protocol (IMAP4)
270 = Microsoft Operations Manager 2004
465 = Simple Mail Transfer over SSL (SMTPS)
515 = TCP/IP Print Server
548 = File Server for Macintosh
554 = Windows Media Services
563 = Network News Transfer Protocol over TLS/SSL (NNTPS)
992 = Telnet �ber TLS/SSL
993 = IMAP4 �ber TLS/SSL (IMAP4S)
995 = POP3 �ber TLS/SSL (POP3S)
1270 = MOM-Encrypted Microsoft Operations Manager 2000
1433 = Microsoft-SQL-Server
1434 = Microsoft-SQL-Monitor
1723 = Routing and Remote Access (PPTP)
1755 = Windows Media Services (MMS)
2393 = OLAP Services 7.0 SQL Server: Downlevel OLAP Client Support
2394 = OLAP Services 7.0 SQL Server: Downlevel OLAP Client Support
2725 = SQL Analysis Services SQL 2000 Analysis Server
8080 = HTTP Alternative
51515 = MOM-Clear Microsoft Operations Manager 2000";
for port in ports {
	portlist = portlist + port + "|";
}
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System l�uft Samba, es ist kein\\nMicrosoft Windows System." );
}
else {
	if( ContainsString( OSVER, "none" ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( OSVER == "5.1" || ( OSVER == "5.2" && ContainsString( OSNAME, "Microsoft(R) Windows(R) XP Professional x64 Edition" ) ) || ( OSVER == "6.0" && OSTYPE == 1 ) || ( OSVER == "6.1" && OSTYPE == 1 ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Server." );
		}
		else {
			checkport = split( buffer: portlist, sep: "|", keep: 0 );
			for(c = 0;c < max_index( checkport );c++){
				for(p = 0;p < max_index( portchecklist );p++){
					if(checkport[c] == portchecklist[p]){
						PORTNAME = egrep( pattern: "^" + checkport[c] + " = ", string: PORTTITEL );
						PORTNAME = ereg_replace( pattern: "\n", replace: "", string: PORTNAME );
						RES = RES + "Port: " + PORTNAME + ";\n";
						CHECK = CHECK + 1;
					}
				}
			}
			if( vhdsvc_cap && nvspwmi_cap && vmms_cap ){
				if(vhdsvc_state == "Running" && nvspwmi_state == "Running" && vmms_state == "Running"){
					if( RES ){
						result = NASLString( "nicht erf�llt" );
						desc = NASLString( "Auf dem Server wurde folgende Virtualisierungssoftware\ngefunden:\n" + vmms_cap + "\nFolgende(r) Dienst l�uft neben der Virtualisierungssoftware\nauf dem Server:\n" + RES );
					}
					else {
						result = NASLString( "erf�llt" );
						desc = NASLString( "Auf dem Server wurde folgende Virtualisierungssoftware\ngefunden:\n" + vmms_cap + "\nAuf dem Server laufenen keine weiteren zu �berpr�fenden\nDienste." );
					}
				}
			}
			else {
				if( CHECK > 1 ){
					result = NASLString( "nicht erf�llt" );
					desc = NASLString( "Folgende Dienste laufen auf dem Server:\n" ) + RES;
					desc = desc + NASLString( "\nPr�fen Sie bitte ob alle Dienste n�tig sind." );
				}
				else {
					if( RES ){
						result = NASLString( "erf�llt" );
						desc = NASLString( "Folgender Dienst l�uft alleine auf dem Server:\n" ) + RES;
					}
					else {
						result = NASLString( "erf�llt" );
						desc = NASLString( "Auf dem Server laufen keine zu �berpr�fenden Dienste." ) + RES;
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_097/result", value: result );
set_kb_item( name: "GSHB/M4_097/desc", value: desc );
set_kb_item( name: "GSHB/M4_097/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_097" );
}
exit( 0 );

