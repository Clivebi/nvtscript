func GSHB_read_file( share, file, offset ){
	var share, file, offset;
	var port, soc, name, r, prot, domain, login, pass, uid, tid, fid, size, content;
	port = kb_smb_transport();
	if(!port){
		port = 445;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return FALSE;
	}
	name = kb_smb_name();
	r = smb_session_request( soc: soc, remote: name );
	if(!r){
		close( soc );
		return FALSE;
	}
	prot = smb_neg_prot( soc: soc );
	if(!prot){
		close( soc );
		return FALSE;
	}
	domain = kb_smb_domain();
	login = kb_smb_login();
	pass = kb_smb_password();
	r = smb_session_setup( soc: soc, login: login, password: pass, domain: domain, prot: prot );
	if(!r){
		close( soc );
		return FALSE;
	}
	uid = session_extract_uid( reply: r );
	if(!uid){
		close( soc );
		return FALSE;
	}
	r = smb_tconx( soc: soc, name: name, uid: uid, share: share );
	if(!r){
		close( soc );
		return FALSE;
	}
	tid = tconx_extract_tid( reply: r );
	if(!tid){
		close( soc );
		return FALSE;
	}
	fid = OpenAndX( socket: soc, uid: uid, tid: tid, file: file );
	if(!fid){
		close( soc );
		return FALSE;
	}
	size = smb_get_file_size( socket: soc, uid: uid, tid: tid, fid: fid );
	if(!size){
		close( soc );
		return FALSE;
	}
	content = ReadAndX( socket: soc, uid: uid, tid: tid, fid: fid, count: size, off: offset );
	return content;
}

