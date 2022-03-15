CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80007" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 950 );
	script_cve_id( "CVE-2000-0097" );
	script_name( "Microsoft MS00-06 security check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Christian Eric Edjenguele" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-006.asp" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "The WebHits ISAPI filter in Microsoft Index Server allows remote attackers to read arbitrary files,
  aka the 'Malformed Hit-Highlighting Argument' vulnerability MS00-06." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
pages = make_list( "default.asp",
	 "iisstart.asp",
	 "localstart.asp",
	 "index.asp" );
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
for asp_file in pages {
	url = NASLString( "/null.htw?CiWebHitsFile=/" + asp_file + "%20&CiRestriction=none&CiHiliteType=Full" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(res){
		r = tolower( res );
		if(ContainsString( r, "Microsoft-IIS" ) && egrep( pattern: "^HTTP/1.[01] 200", string: r ) && ContainsString( r, "<html>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

