if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800274" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "UltraISO Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of UltraISO." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "UltraISO Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	ultraName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( ultraName, "UltraISO" )){
		path = registry_get_sz( key: key + item, item: "DisplayIcon" );
		if(path == NULL){
			continue;
		}
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
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
		if(!r){
			close( soc );
			exit( 0 );
		}
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
		v = GetVersion( socket: soc, uid: uid, tid: tid, fid: fid, offset: 1174636 );
		close( soc );
		if(v != NULL){
			set_kb_item( name: "UltraISO/Ver", value: v );
			log_message( data: "UltraISO version " + v + " was detected on the host" );
			cpe = build_cpe( value: v, exp: "^([0-9.]+)", base: "cpe:/a:ezbsystems:ultraiso:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
		exit( 0 );
	}
}

