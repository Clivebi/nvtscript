if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902660" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2011-0661" );
	script_bugtraq_id( 47198 );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-06 11:57:33 +0530 (Tue, 06 Mar 2012)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft SMB Transaction Parsing Remote Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_smb_accessible_shares.sc", "os_detection.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "SMB/Accessible_Shares", "Host/runs_windows" );
	script_require_ports( 139, 445 );
	script_exclude_keys( "SMB/samba" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1025329" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA11-102A.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-020" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code on the system." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 SP1 and prior

  - Microsoft Windows 2008 SP2 and prior

  - Microsoft Windows Vista SP2 and prior

  - Microsoft Windows 2008 R2 SP1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of field in SMB request,
  which allows remote attackers to execute arbitrary code on the system by
  sending a malformed SMB request." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-020." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-020" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
if(kb_smb_is_samba()){
	exit( 0 );
}
name = kb_smb_name();
domain = kb_smb_domain();
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
soc1 = open_sock_tcp( port );
if(!soc1){
	exit( 0 );
}
if(!login){
	login = "anonymous";
}
if(!pass){
	pass = "";
}
shares = get_kb_list( "SMB/Accessible_Shares" );
if(isnull( shares )){
	close( soc1 );
	exit( 0 );
}
prot = smb_neg_prot( soc: soc1 );
if(!prot){
	close( soc1 );
	exit( 0 );
}
if(strlen( prot ) < 5){
	exit( 0 );
}
if(ord( prot[4] ) == 254){
	close( soc1 );
	soc1 = open_sock_tcp( port );
	if(!soc1){
		exit( 0 );
	}
	r = smb_session_request( soc: soc1, remote: name );
	if(!r){
		close( soc1 );
		exit( 0 );
	}
	prot = smb_neg_prot_NTLMv1( soc: soc1 );
	if(!prot){
		close( soc1 );
		exit( 0 );
	}
}
r = smb_session_setup( soc: soc1, login: login, password: pass, domain: domain, prot: prot );
if(!r){
	close( soc1 );
	exit( 0 );
}
uid = session_extract_uid( reply: r );
if(!uid){
	close( soc1 );
	exit( 0 );
}
for share in shares {
	r = smb_tconx( soc: soc1, name: name, uid: uid, share: share );
	if(!r){
		continue;
	}
	tid = tconx_extract_tid( reply: r );
	if(!tid){
		continue;
	}
	tid_high = tid / 256;
	tid_low = tid % 256;
	uid_high = uid / 256;
	uid_low = uid % 256;
	resp = FindFirst2( socket: soc1, uid: uid, tid: tid, pattern: "\\*" );
	if(!resp){
		continue;
	}
	for file in resp {
		file = "\\" + file;
		fid = OpenAndX( socket: soc1, uid: uid, tid: tid, file: file );
		if(!fid){
			continue;
		}
		fid_high = fid / 256;
		fid_low = fid % 256;
		smb_read_andx_req = raw_string( 0x00, 0x00, 0x00, 0x3c, 0xff, 0x53, 0x4d, 0x42, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xc8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x33, 0x0c, uid_low, uid_high, 0x80, 0x01, 0x0c, 0xff, 0x00, 0x00, 0x00, fid_low, fid_high, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x00, 0x0a, 0x00, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00 );
		send( socket: soc1, data: smb_read_andx_req );
		read_resp = smb_recv( socket: soc1 );
		smb_close_request( soc: soc1, uid: uid, tid: tid, fid: fid );
		if(strlen( read_resp ) < 13){
			continue;
		}
		if(read_resp && ord( read_resp[9] ) == 13 && ord( read_resp[10] ) == 0 && ord( read_resp[11] ) == 0 && ord( read_resp[12] ) == 192){
			security_message( port );
			close( soc1 );
			exit( 0 );
		}
	}
}
close( soc1 );

