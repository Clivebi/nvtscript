if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800367" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DesignWorks Professional Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of DesignWorks
  Professional." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "DesignWorks Professional Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Capilano" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	if(ContainsString( registry_get_sz( key: key + item, item: "DisplayName" ), "DesignWorks Professional" )){
		exePath = registry_get_sz( key: key + item, item: "UninstallString" );
		exePath = eregmatch( pattern: "([A-Za-z0-9:.\\]+) (.*)", string: exePath );
		if(exePath[2] == NULL){
			exit( 0 );
		}
		exePath = exePath[2] - "\\uninstal.log" + "\\System.dll";
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath );
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
		dwpVer = GetVersion( socket: soc, uid: uid, tid: tid, fid: fid, verstr: "prod" );
		close( soc );
		if(dwpVer != NULL){
			set_kb_item( name: "DesignWorks/Prof/Ver", value: dwpVer );
			log_message( data: "DesignWorks Professional version " + dwpVer + " was" + " detected on the host" );
			cpe = build_cpe( value: dwpVer, exp: "^([0-9.]+)", base: "cpe:/a:capilano:designworks:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
		exit( 0 );
	}
}

