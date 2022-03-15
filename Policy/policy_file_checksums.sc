if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103940" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_name( "File Checksums" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2013-08-14 16:47:16 +0200 (Wed, 14 Aug 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "Policy" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-20.08/en/compliance-and-special-scans.html#checking-file-checksums" );
	script_add_preference( name: "Target checksum File", type: "file", value: "", id: 1 );
	script_add_preference( name: "List all and not only the first 100 entries", type: "checkbox", value: "no", id: 2 );
	script_tag( name: "summary", value: "Checks the checksums (MD5 or SHA1)of specified files.

  The SSH protocol is used to log in and to gather the needed information." );
	script_tag( name: "qod", value: "98" );
	script_timeout( 600 );
	exit( 0 );
}
checksumlist = script_get_preference( name: "Target checksum File", id: 1 );
if(!checksumlist){
	exit( 0 );
}
checksumlist = script_get_preference_file_content( name: "Target checksum File", id: 1 );
if(!checksumlist){
	exit( 0 );
}
require("ssh_func.inc.sc");
func check_md5( md5 ){
	var md5;
	if( ereg( pattern: "^[a-f0-9]{32}$", string: md5 ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func check_sha1( sha1 ){
	var sha1;
	if( ereg( pattern: "^[a-f0-9]{40}$", string: sha1 ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func check_ip( ip ){
	var ip;
	if( ereg( pattern: "([0-9]{1,3}\\.){3}[0-9]{1,3}$", string: ip ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func check_file( file ){
	var file, unallowed, ua;
	unallowed = make_list( "#",
		 ">",
		 "<",
		 ";",
		 "\0",
		 "!",
		 "'",
		 "\"",
		 "$",
		 "%",
		 "&",
		 "(",
		 ")",
		 "?",
		 "`",
		 "*",
		 " |",
		 "}",
		 "{",
		 "[",
		 "]" );
	for ua in unallowed {
		if(ContainsString( file, ua )){
			return FALSE;
		}
	}
	if( !ereg( pattern: "^/.*$", string: file ) ) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}
listall = script_get_preference( name: "List all and not only the first 100 entries", id: 2 );
maxlist = 100;
host_ip = get_host_ip();
valid_lines_list = make_list();
set_kb_item( name: "policy/file_checksums/started", value: TRUE );
lines = split( buffer: checksumlist, keep: FALSE );
line_count = max_index( lines );
if(line_count == 1 && IsMatchRegexp( lines[0], "Checksum\\|File\\|Checksumtype(\\|Only-Check-This-IP)?" )){
	set_kb_item( name: "policy/file_checksums/general_error_list", value: "Attached checksum File doesn't contain test entries (Only the header is present)." );
	exit( 0 );
}
x = 0;
for line in lines {
	x++;
	if(!eregmatch( pattern: "((Checksum\\|File\\|Checksumtype(\\|Only-Check-This-IP)?)|([a-f0-9]{32,40}\\|.*\\|(sha1|md5)))", string: line )){
		if(x == line_count && eregmatch( pattern: "^$", string: line )){
			continue;
		}
		set_kb_item( name: "policy/file_checksums/invalid_list", value: line + "|invalid line error|error;" );
		continue;
	}
	if(!eregmatch( pattern: "(Checksum\\|File\\|Checksumtype(\\|Only-Check-This-IP)?)", string: line )){
		valid_lines_list = make_list( valid_lines_list,
			 line );
	}
}
port = kb_ssh_transport();
sock = ssh_login_or_reuse_connection();
if(!sock){
	error = ssh_get_error();
	if(!error){
		error = "No SSH Port or Connection!";
	}
	set_kb_item( name: "policy/file_checksums/general_error_list", value: error );
	exit( 0 );
}
if( listall == "yes" ){
	max = max_index( valid_lines_list );
}
else {
	maxindex = max_index( valid_lines_list );
	if( maxindex < maxlist ) {
		max = maxindex;
	}
	else {
		max = maxlist;
	}
}
for(i = 0;i < max;i++){
	val = split( buffer: valid_lines_list[i], sep: "|", keep: FALSE );
	checksum = tolower( val[0] );
	filename = val[1];
	algorithm = tolower( val[2] );
	if(max_index( val ) == 4){
		ip = val[3];
		if(!check_ip( ip: ip )){
			set_kb_item( name: "policy/file_checksums/invalid_list", value: valid_lines_list[i] + "|ip format error|error;" );
			continue;
		}
		if(ip && ip != host_ip){
			continue;
		}
	}
	if(!checksum || !filename || !algorithm){
		set_kb_item( name: "policy/file_checksums/invalid_list", value: valid_lines_list[i] + "|error reading line|error;" );
		continue;
	}
	if(!check_file( file: filename )){
		set_kb_item( name: "policy/file_checksums/invalid_list", value: valid_lines_list[i] + "|filename format error|error;" );
		continue;
	}
	if( algorithm == "md5" ){
		if(!check_md5( md5: checksum )){
			set_kb_item( name: "policy/file_checksums/invalid_list", value: valid_lines_list[i] + "|md5 format error|error;" );
			continue;
		}
		sshval = ssh_cmd( socket: sock, cmd: "LC_ALL=C md5sum " + " '" + filename + "'" );
		if( !IsMatchRegexp( sshval, ".*No such file or directory" ) ){
			md5val = split( buffer: sshval, sep: " ", keep: FALSE );
			if( tolower( md5val[0] ) == checksum ){
				set_kb_item( name: "policy/file_checksums/md5_ok_list", value: filename + "|" + md5val[0] + "|pass;" );
			}
			else {
				set_kb_item( name: "policy/file_checksums/md5_violation_list", value: filename + "|" + md5val[0] + "|fail;" );
			}
		}
		else {
			set_kb_item( name: "policy/file_checksums/md5_error_list", value: filename + "|No such file or directory|error;" );
		}
	}
	else {
		if(algorithm == "sha1"){
			if(!check_sha1( sha1: checksum )){
				set_kb_item( name: "policy/file_checksums/general_error_list", value: valid_lines_list[i] + "|sha1 format error|error;" );
				continue;
			}
			sshval = ssh_cmd( socket: sock, cmd: "LC_ALL=C sha1sum " + " '" + filename + "'" );
			if( !IsMatchRegexp( sshval, ".*No such file or directory" ) ){
				sha1val = split( buffer: sshval, sep: " ", keep: FALSE );
				if( tolower( sha1val[0] ) == checksum ){
					set_kb_item( name: "policy/file_checksums/sha1_ok_list", value: filename + "|" + sha1val[0] + "|pass;" );
				}
				else {
					set_kb_item( name: "policy/file_checksums/sha1_violation_list", value: filename + "|" + sha1val[0] + "|fail;" );
				}
			}
			else {
				set_kb_item( name: "policy/file_checksums/sha1_error_list", value: filename + "|No such file or directory|error;" );
			}
		}
	}
}
exit( 0 );

