CPE = "cpe:/a:gnu:bash";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802086" );
	script_version( "2020-08-24T11:37:53+0000" );
	script_cve_id( "CVE-2014-6277" );
	script_bugtraq_id( 70165 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 11:37:53 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-10-08 12:11:49 +0530 (Wed, 08 Oct 2014)" );
	script_name( "GNU Bash Environment Variable Handling Shell RCE Vulnerability (LSC) - 04" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_gnu_bash_detect_lin.sc" );
	script_mandatory_keys( "bash/linux/detected" );
	script_exclude_keys( "ssh/force/pty" );
	script_xref( name: "URL", value: "https://shellshocker.net" );
	script_xref( name: "URL", value: "http://lcamtuf.blogspot.in/2014/09/bash-bug-apply-unofficial-patch-now.html" );
	script_tag( name: "summary", value: "This host is installed with GNU Bash Shell
  and is prone to remote command execution vulnerability." );
	script_tag( name: "vuldetect", value: "Login to the target machine with ssh
  credentials and check its possible to execute the commands via GNU bash shell." );
	script_tag( name: "insight", value: "GNU bash contains a flaw that is triggered
  when evaluating environment variables passed from another environment.
  After processing a function definition, bash continues to process trailing
  strings. Incomplete fix to CVE-2014-7169, CVE-2014-6271." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  or local attackers to inject  shell commands, allowing local privilege
  escalation or remote command execution depending on the application vector." );
	script_tag( name: "affected", value: "GNU Bash through 4.3 bash43-026." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
if(get_kb_item( "ssh/force/pty" )){
	exit( 0 );
}
if(!bin = get_app_location( cpe: CPE, port: 0 )){
	exit( 0 );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
if( bin == "unknown" ) {
	bash_cmd = "bash";
}
else {
	if( IsMatchRegexp( bin, "^/.*bash$" ) ) {
		bash_cmd = bin;
	}
	else {
		exit( 0 );
	}
}
cmd = "echo \"" + "vt_test='() { x() { _;}; x() { _;} <<a; }' " + bash_cmd + " -c date 2>/dev/null || echo CVE-2014-6277 vulnerable" + "\" | " + bash_cmd;
result = ssh_cmd( socket: sock, cmd: cmd, nosh: TRUE );
close( sock );
if(ContainsString( result, "Unsupported use of" )){
	exit( 99 );
}
if(ContainsString( result, "CVE-2014-6277 vulnerable" )){
	report = "Used command: " + cmd + "\n\nResult: " + result;
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

