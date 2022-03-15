if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96079" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Read configs to prevent root login " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Read configs to prevent root login:

  Check for /etc/securettys show all non console, check if root login is not
  possible via SSH, check for SYSLOG_SU_ENAB in /etc/login.defs,
  check for perm 0644 on /etc/securettys /etc/login.defs /etc/sshd/sshd_config,
  check if root_squash is enabled on all NFS mounts" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = get_preference( "auth_port_ssh" );
if(!port){
	port = ssh_get_port( default: 22, ignore_unscanned: TRUE );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	error = ssh_get_error();
	if(!error){
		error = "No SSH Port or Connection!";
	}
	log_message( port: port, data: error );
	set_kb_item( name: "GSHB/securetty", value: "error" );
	set_kb_item( name: "GSHB/sshdconfig", value: "error" );
	set_kb_item( name: "GSHB/logindefs", value: "error" );
	set_kb_item( name: "GSHB/nfsexports", value: "error" );
	set_kb_item( name: "GSHB/securetty/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/securetty", value: "windows" );
	set_kb_item( name: "GSHB/sshdconfig", value: "windows" );
	set_kb_item( name: "GSHB/logindefs", value: "windows" );
	set_kb_item( name: "GSHB/nfsexports", value: "windows" );
	exit( 0 );
}
uname = get_kb_item( "ssh/login/uname" );
uname = ereg_replace( pattern: "\n", replace: "", string: uname );
securetty = ssh_cmd( socket: sock, cmd: "LANG=C cat /etc/securetty" );
sshdconfig = ssh_cmd( socket: sock, cmd: "LANG=C cat /etc/ssh/sshd_config" );
logindefs = ssh_cmd( socket: sock, cmd: "LANG=C cat /etc/login.defs" );
nfsexports = ssh_cmd( socket: sock, cmd: "LANG=C cat /etc/exports" );
lssecuretty = ssh_cmd( socket: sock, cmd: "LANG=C ls -l /etc/securetty" );
lssshdconfig = ssh_cmd( socket: sock, cmd: "LANG=C ls -l /etc/ssh/sshd_config" );
lslogindefs = ssh_cmd( socket: sock, cmd: "LANG=C ls -l /etc/login.defs" );
if( ContainsString( securetty, "cat: command not found" ) ) {
	securetty = "nocat";
}
else {
	if( ContainsString( securetty, "cat: /etc/securetty: Permission denied" ) ) {
		securetty = "noperm";
	}
	else {
		if( ContainsString( securetty, "cat: cannot access /etc/securetty:" ) ) {
			securetty = "none";
		}
		else {
			if( ContainsString( securetty, "cat: cannot open /etc/securetty" ) ) {
				securetty = "none";
			}
			else {
				if( ContainsString( securetty, "cat: /etc/securetty:" ) ) {
					securetty = "none";
				}
				else {
					Lst = split( buffer: securetty, keep: 0 );
					for(i = 0;i < max_index( Lst );i++){
						result = eregmatch( string: Lst[i], pattern: "^ *#", icase: 0 );
						if(!result){
							if(!IsMatchRegexp( Lst[i], "^tty.*" ) && Lst[i] != "" && !IsMatchRegexp( Lst[i], "(C|c)(O|o)(N|n)(S|s)(O|o)(L|l)(E|e)" )){
								if(!IsMatchRegexp( Lst[i], "^:[0-9]{1}.*" )){
									nonsecuretty += Lst[i] + "\n";
								}
							}
						}
					}
					if( nonsecuretty ) {
						securetty = nonsecuretty;
					}
					else {
						securetty = "secure";
					}
				}
			}
		}
	}
}
if( ContainsString( sshdconfig, "cat: command not found" ) ) {
	sshdconfig = "nocat";
}
else {
	if( ContainsString( sshdconfig, "cat: /etc/ssh/sshd_config: Permission denied" ) ) {
		sshdconfig = "noperm";
	}
	else {
		if( ContainsString( sshdconfig, "cat: cannot access /etc/ssh/sshd_config:" ) ) {
			sshdconfig = "none";
		}
		else {
			if( ContainsString( sshdconfig, "cat: /etc/ssh/sshd_config:" ) ) {
				sshdconfig = "none";
			}
			else {
				rootlogin = egrep( string: sshdconfig, pattern: "PermitRootLogin", icase: 0 );
				Lst = split( buffer: rootlogin, keep: 0 );
				if( Lst ){
					for(i = 0;i < max_index( Lst );i++){
						result = eregmatch( string: Lst[i], pattern: "^ *#", icase: 0 );
						if(!result){
							login += Lst[i];
						}
					}
				}
				else {
					result = eregmatch( string: rootlogin, pattern: "^ *#", icase: 0 );
					if(!result){
						login = rootlogin;
					}
				}
				rootlogin = eregmatch( string: login, pattern: "yes", icase: 0 );
				if( !rootlogin ) {
					sshdconfig = "norootlogin";
				}
				else {
					sshdconfig = "rootlogin";
				}
			}
		}
	}
}
if( ContainsString( logindefs, "cat: command not found" ) ) {
	logindefs = "nocat";
}
else {
	if( ContainsString( logindefs, "cat: /etc/login.defs: Permission denied" ) ) {
		logindefs = "noperm";
	}
	else {
		if( ContainsString( logindefs, "cat: cannot access /etc/login.defs:" ) ) {
			logindefs = "none";
		}
		else {
			if( ContainsString( logindefs, "cat: /etc/login.defs:" ) ) {
				logindefs = "none";
			}
			else {
				syslogsuenab = egrep( string: logindefs, pattern: "SYSLOG_SU_ENAB", icase: 0 );
				Lst = split( buffer: syslogsuenab, keep: 0 );
				if( Lst ){
					for(i = 0;i < max_index( Lst );i++){
						result = eregmatch( string: Lst[i], pattern: "^ *#", icase: 0 );
						if(!result){
							syslog += Lst[i] + "\n";
						}
					}
				}
				else {
					result = eregmatch( string: syslogsuenab, pattern: "^ *#", icase: 0 );
					if(!result){
						syslog = syslogsuenab;
					}
				}
				syslogenab = eregmatch( string: syslog, pattern: "yes", icase: 0 );
				if( !syslogenab ) {
					logindefs = "nosyslogsuenab";
				}
				else {
					logindefs = "syslogsuenab";
				}
			}
		}
	}
}
if( !nfsexports ) {
	nfsexports = "none";
}
else {
	if( ContainsString( securetty, "cat: command not found" ) ) {
		nfsexports = "nocat";
	}
	else {
		if( ContainsString( nfsexports, "cat: /etc/exports: Permission denied" ) ) {
			nfsexports = "noperm";
		}
		else {
			if( ContainsString( nfsexports, "cat: cannot access /etc/exports:" ) ) {
				nfsexports = "none";
			}
			else {
				if( ContainsString( nfsexports, "cat: cannot open /etc/exports:" ) ) {
					nfsexports = "none";
				}
				else {
					if( ContainsString( nfsexports, "cat: /etc/exports:" ) ) {
						nfsexports = "none";
					}
					else {
						org_nfsexports = nfsexports;
						Lst = split( buffer: nfsexports, keep: 0 );
						for(i = 0;i < max_index( Lst );i++){
							result = eregmatch( string: Lst[i], pattern: "^ *#", icase: 0 );
							if(!result){
								result = eregmatch( string: Lst[i], pattern: " */.*", icase: 0 );
								if(result){
									val += result[0] + "\n";
								}
							}
						}
						nfsexports = val;
						Lst = split( buffer: nfsexports, keep: 0 );
						if( Lst ){
							for(i = 0;i < max_index( Lst );i++){
								result = eregmatch( string: Lst[i], pattern: "no_root_squash", icase: 0 );
								if( !result ){
									result = eregmatch( string: Lst[i], pattern: "root_squash", icase: 0 );
									if( result ) {
										rootsquash += Lst[i] + "\n";
									}
									else {
										if(!IsMatchRegexp( Lst[i], "^ *\n" ) && Lst[i] != ""){
											norootsquash += Lst[i] + "\n";
										}
									}
								}
								else {
									if(!IsMatchRegexp( Lst[i], "^ *\n" ) && Lst[i] != ""){
										norootsquash += Lst[i] + "\n";
									}
								}
							}
						}
						else {
							result = eregmatch( string: nfsexports, pattern: "no_root_squash", icase: 0 );
							if( !result ){
								result = eregmatch( string: nfsexports, pattern: "root_squash", icase: 0 );
								if( result ) {
									rootsquash = nfsexports;
								}
								else {
									norootsquash = nfsexports;
								}
							}
							else {
								norootsquash = nfsexports;
							}
						}
						if(IsMatchRegexp( norootsquash, "^ *\n" )){
							norootsquash = "none";
						}
						if(IsMatchRegexp( rootsquash, "^ *\n" )){
							rootsquash = "none";
						}
						if(!nfsexports && org_nfsexports){
							nfsexports = org_nfsexports;
						}
					}
				}
			}
		}
	}
}
if( IsMatchRegexp( lssecuretty, ".*No such file or directory.*" ) ) {
	lssecuretty = "none";
}
else {
	if( !lssecuretty ) {
		lssecuretty = "none";
	}
	else {
		Lst = split( buffer: lssecuretty, sep: " ", keep: 0 );
		lssecuretty = Lst[0] + ":" + Lst[2] + ":" + Lst[3];
	}
}
if( IsMatchRegexp( lssshdconfig, ".*No such file or directory.*" ) ) {
	lssshdconfig = "none";
}
else {
	if( !lssshdconfig ) {
		lssshdconfig = "none";
	}
	else {
		Lst = split( buffer: lssshdconfig, sep: " ", keep: 0 );
		lssshdconfig = Lst[0] + ":" + Lst[2] + ":" + Lst[3];
	}
}
if( IsMatchRegexp( lslogindefs, ".*No such file or directory.*" ) ) {
	lslogindefs = "none";
}
else {
	if( !lslogindefs ) {
		lslogindefs = "none";
	}
	else {
		Lst = split( buffer: lslogindefs, sep: " ", keep: 0 );
		lslogindefs = Lst[0] + ":" + Lst[2] + ":" + Lst[3];
	}
}
if(!norootsquash){
	norootsquash = "none";
}
if(!rootsquash){
	rootsquash = "none";
}
set_kb_item( name: "GSHB/securetty/nonconsole", value: securetty );
set_kb_item( name: "GSHB/sshdconfig/PermitRootLogin", value: sshdconfig );
set_kb_item( name: "GSHB/logindefs/syslogsuenab", value: logindefs );
set_kb_item( name: "GSHB/nfsexports", value: nfsexports );
set_kb_item( name: "GSHB/nfsexports/norootsquash", value: norootsquash );
set_kb_item( name: "GSHB/nfsexports/rootsquash", value: rootsquash );
set_kb_item( name: "GSHB/securetty/perm", value: lssecuretty );
set_kb_item( name: "GSHB/sshdconfig/perm", value: lssshdconfig );
set_kb_item( name: "GSHB/logindefs/perm", value: lslogindefs );
set_kb_item( name: "GSHB/uname", value: uname );
exit( 0 );

