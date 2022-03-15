if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96100" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-21 10:39:50 +0200 (Mon, 21 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Check for rlogin, rsh, rcp tools and configuration" );
	script_category( ACT_GATHER_INFO );
	script_timeout( 2400 );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "Check for rlogin, rsh, rcp tools and configuration

  Lists /etc/inetd.conf, /etc/hosts.equiv, /etc/ftpusers,
  searches for .rhost, .netrc, rlogind and rshd" );
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
	set_kb_item( name: "GSHB/R-TOOL/rhosts", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/hostsequiv", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/lshostsequiv", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/inetdconf", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/ftpusers", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/rlogind", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/rshd", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/netrc", value: "error" );
	set_kb_item( name: "GSHB/R-TOOL/log", value: "error" );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/R-TOOL/rhosts", value: "windows" );
	set_kb_item( name: "GSHB/R-TOOL/hostsequiv", value: "windows" );
	set_kb_item( name: "GSHB/R-TOOL/lshostsequiv", value: "windows" );
	set_kb_item( name: "GSHB/R-TOOL/inetdconf", value: "windows" );
	set_kb_item( name: "GSHB/R-TOOL/ftpusers", value: "windows" );
	set_kb_item( name: "GSHB/R-TOOL/rlogind", value: "windows" );
	set_kb_item( name: "GSHB/R-TOOL/rshd", value: "windows" );
	set_kb_item( name: "GSHB/R-TOOL/netrc", value: "windows" );
	exit( 0 );
}
rhosts = ssh_cmd( socket: sock, cmd: "LANG=C locate .rhosts" );
if( !rhosts ) {
	rhosts = "not found";
}
else {
	if(ContainsString( rhosts, "locate:" )){
		rhosts = ssh_cmd( socket: sock, cmd: "LANG=C mlocate .rhosts" );
	}
}
if( !rhosts ) {
	rhosts = "not found";
}
else {
	if(ContainsString( rhosts, "mlocate:" )){
		rhosts = ssh_cmd( socket: sock, cmd: "LANG=C slocate .rhosts" );
	}
}
if( !rhosts ) {
	rhosts = "not found";
}
else {
	if(ContainsString( rhosts, "slocate:" )){
		rhosts = ssh_cmd( socket: sock, cmd: "LANG=C find / -name .rhosts" );
	}
}
if(!rhosts){
	rhosts = "not found";
}
if(rhosts != "not found"){
	val = "";
	Lst = split( buffer: rhosts, keep: 0 );
	if(max_index( Lst ) > 1){
		for(i = 0;i < max_index( Lst );i++){
			if(IsMatchRegexp( Lst[i], ".*Permission denied$" )){
				continue;
			}
			val += Lst[i] + "\n";
		}
		if( val ) {
			rhosts = val;
		}
		else {
			rhosts = "not found";
		}
	}
}
lshostsequiv = ssh_cmd( socket: sock, cmd: "LANG=C ls -l /etc/hosts.equiv" );
if(IsMatchRegexp( lshostsequiv, ".*No such file or directory.*" )){
	lshostsequiv = "none";
}
if( lshostsequiv != "none" ){
	hostsequiv = ssh_cmd( socket: sock, cmd: "LANG=C grep -v '^#' /etc/hosts.equiv" );
	if(hostsequiv == "" || IsMatchRegexp( hostsequiv, "^.?$" )){
		hostsequiv = "noentry";
	}
}
else {
	hostsequiv = "none";
}
inetdconf = ssh_cmd( socket: sock, cmd: "LANG=C grep -v '^#' /etc/inetd.conf" );
if( inetdconf == "" || IsMatchRegexp( inetdconf, "^.?$" ) ) {
	inetdconf = "noentry";
}
else {
	if(ContainsString( inetdconf, "cat: /etc/inetd.conf:" )){
		inetdconf = "none";
	}
}
ftpusers = ssh_cmd( socket: sock, cmd: "LANG=C grep -v '^#' /etc/ftpusers" );
if( ftpusers == "" || IsMatchRegexp( ftpusers, "^.?$" ) ) {
	ftpusers = "noentry";
}
else {
	if(ContainsString( ftpusers, "cat: /etc/ftpusers:" )){
		ftpusers = "none";
	}
}
rlogind = ssh_cmd( socket: sock, cmd: "LANG=C locate rlogind" );
if( !rlogind ) {
	rlogind = "not found";
}
else {
	if(ContainsString( rlogind, "locate:" )){
		rlogind = ssh_cmd( socket: sock, cmd: "LANG=C mlocate rlogind" );
	}
}
if( !rlogind ) {
	rlogind = "not found";
}
else {
	if(ContainsString( rlogind, "mlocate:" )){
		rlogind = ssh_cmd( socket: sock, cmd: "LANG=C slocate rlogind" );
	}
}
if( !rlogind ) {
	rlogind = "not found";
}
else {
	if(ContainsString( rlogind, "slocate:" )){
		rlogind = ssh_cmd( socket: sock, cmd: "LANG=C find / -name rlogind" );
	}
}
if(!rlogind){
	rlogind = "not found";
}
rlogind = "not found";
if(rlogind != "not found"){
	val = "";
	Lst = split( buffer: rlogind, keep: 0 );
	if( max_index( Lst ) > 1 ){
		for(i = 0;i < max_index( Lst );i++){
			if(!IsMatchRegexp( Lst[i], ".*/rlogind$" )){
				continue;
			}
			val += Lst[i] + "\n";
		}
		if( val ) {
			rlogind = val;
		}
		else {
			rlogind = "not found";
		}
	}
	else {
		if(!IsMatchRegexp( rlogind, ".*/rlogind$" )){
			rlogind = "not found";
		}
	}
}
rshd = ssh_cmd( socket: sock, cmd: "LANG=C locate rshd" );
if( !rshd ) {
	rshd = "not found";
}
else {
	if(ContainsString( rshd, "locate:" )){
		rshd = ssh_cmd( socket: sock, cmd: "LANG=C mlocate rshd" );
	}
}
if( !rshd ) {
	rshd = "not found";
}
else {
	if(ContainsString( rshd, "mlocate:" )){
		rshd = ssh_cmd( socket: sock, cmd: "LANG=C slocate rshd" );
	}
}
if( !rshd ) {
	rshd = "not found";
}
else {
	if(ContainsString( rshd, "slocate:" )){
		rshd = ssh_cmd( socket: sock, cmd: "LANG=C find / -name rshd" );
	}
}
if(!rshd){
	rshd = "not found";
}
if(rshd != "not found"){
	Lst = split( buffer: rshd, keep: 0 );
	if( max_index( Lst ) > 1 ){
		val = "";
		for(i = 0;i < max_index( Lst );i++){
			if(!IsMatchRegexp( Lst[i], ".*/rshd$" )){
				continue;
			}
			val += Lst[i] + "\n";
		}
		if( val ) {
			rshd = val;
		}
		else {
			rshd = "not found";
		}
	}
	else {
		if(!IsMatchRegexp( rshd, ".*/rshd$" )){
			rshd = "not found";
		}
	}
}
netrc = ssh_cmd( socket: sock, cmd: "LANG=C locate .netrc" );
if( !netrc ) {
	netrc = "not found";
}
else {
	if(ContainsString( rshd, "locate:" )){
		netrc = ssh_cmd( socket: sock, cmd: "LANG=C mlocate .netrc" );
	}
}
if( !netrc ) {
	netrc = "not found";
}
else {
	if(ContainsString( netrc, "mlocate:" )){
		netrc = ssh_cmd( socket: sock, cmd: "LANG=C slocate .netrc" );
	}
}
if( !netrc ) {
	netrc = "not found";
}
else {
	if(ContainsString( netrc, "slocate:" )){
		netrc = ssh_cmd( socket: sock, cmd: "LANG=C find / -name .netrc" );
	}
}
if(!netrc){
	netrc = "not found";
}
if(netrc != "not found"){
	Lst = split( buffer: netrc, keep: 0 );
	if( max_index( Lst ) > 1 ){
		val = "";
		for(i = 0;i < max_index( Lst );i++){
			if(!IsMatchRegexp( Lst[i], ".*/.netrc" )){
				continue;
			}
			val += Lst[i] + "\n";
		}
		if( val ) {
			netrc = val;
		}
		else {
			netrc = "not found";
		}
	}
	else {
		if(!IsMatchRegexp( netrc, ".*/.netrc" )){
			netrc = "not found";
		}
	}
}
set_kb_item( name: "GSHB/R-TOOL/rhosts", value: rhosts );
set_kb_item( name: "GSHB/R-TOOL/hostsequiv", value: hostsequiv );
set_kb_item( name: "GSHB/R-TOOL/lshostsequiv", value: lshostsequiv );
set_kb_item( name: "GSHB/R-TOOL/inetdconf", value: inetdconf );
set_kb_item( name: "GSHB/R-TOOL/ftpusers", value: ftpusers );
set_kb_item( name: "GSHB/R-TOOL/rlogind", value: rlogind );
set_kb_item( name: "GSHB/R-TOOL/rshd", value: rshd );
set_kb_item( name: "GSHB/R-TOOL/netrc", value: netrc );
exit( 0 );

