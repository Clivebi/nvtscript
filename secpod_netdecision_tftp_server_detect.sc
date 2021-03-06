if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900357" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "NetDecision TFTP Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script is detects installed version of NetDecision TFTP Server." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
SCRIPT_DESC = "NetDecision TFTP Server Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\NetDecision" )){
	exit( 0 );
}
netdeciKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for item in registry_enum_keys( key: netdeciKey ) {
	netdeciName = registry_get_sz( key: netdeciKey + item, item: "DisplayName" );
	if(ContainsString( netdeciName, "NetDecision" )){
		netdeciPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
		if(netdeciPath != NULL){
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: netdeciPath );
			file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: netdeciPath + "\\NetDecision\\Bin\\TFTPServer.exe" );
			name = kb_smb_name();
			login = kb_smb_login();
			pass = kb_smb_password();
			domain = kb_smb_domain();
			port = kb_smb_transport();
			soc = open_sock_tcp( port );
			if(!soc){
				exit( 0 );
			}
			r = smb_session_request( soc: soc, remote: name );
			if(!r){
				close( soc );
				exit( 0 );
			}
			prot = smb_neg_prot( soc: soc );
			if(!prot){
				close( soc );
				exit( 0 );
			}
			r = smb_session_setup( soc: soc, login: login, password: pass, domain: domain, prot: prot );
			if(!r){
				close( soc );
				exit( 0 );
			}
			uid = session_extract_uid( reply: r );
			if(!uid){
				close( soc );
				exit( 0 );
			}
			r = smb_tconx( soc: soc, name: name, uid: uid, share: share );
			tid = tconx_extract_tid( reply: r );
			if(!tid){
				close( soc );
				exit( 0 );
			}
			fid = OpenAndX( socket: soc, uid: uid, tid: tid, file: file );
			if(!fid){
				close( soc );
				exit( 0 );
			}
		}
		netdeciVer = GetVersion( socket: soc, uid: uid, tid: tid, fid: fid, verstr: "prod" );
		close( soc );
		if(netdeciVer){
			set_kb_item( name: "NetDecision/TFTP/Ver", value: netdeciVer );
			log_message( data: "NetDecision TFTP Server version " + netdeciVer + " was detected on the host" );
			cpe = build_cpe( value: netdeciVer, exp: "^([0-9.]+)", base: "cpe:/a:netmechanica:netdecision_tftp_server:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
		exit( 0 );
	}
}

