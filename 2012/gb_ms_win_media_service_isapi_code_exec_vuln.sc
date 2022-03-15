CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802897" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_cve_id( "CVE-2003-0227", "CVE-2003-0349" );
	script_bugtraq_id( 7727, 8035 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-07-25 16:04:16 +0530 (Wed, 25 Jul 2012)" );
	script_name( "Microsoft Windows Media Services ISAPI Extension Code Execution Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/9115" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/8883" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1007059" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/113716" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-019" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-022" );
	script_xref( name: "URL", value: "http://support.microsoft.com/default.aspx?scid=kb;en-us;822343" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to obtain sensitive
  information, execute arbitrary code or cause denial of service conditions." );
	script_tag( name: "affected", value: "- Microsoft Windows Media Services 4.0 and 4.1

  - Microsoft Windows NT 4.0

  - Microsoft Windows 2000" );
	script_tag( name: "insight", value: "Windows Media Services logging capability for multicast transmissions is
  implemented as ISAPI extension (nsiislog.dll), which fails to processes
  incoming client or malicious HTTP requests." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is running Microsoft Windows Media Services and is prone
  to remote code execution vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url = "/scripts/nsiislog.dll";
iisreq = http_get( item: url, port: port );
iisres = http_keepalive_send_recv( port: port, data: iisreq, bodyonly: FALSE );
if(!iisres || !ContainsString( iisres, ">NetShow ISAPI Log Dll" )){
	exit( 0 );
}
postData = crap( data: "A", length: 70000 );
host = http_host_name( port: port );
iisreq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", postData );
iisres = http_send_recv( port: port, data: iisreq );
if(iisres && ContainsString( iisres, "HTTP/1.1 500 Server Error" ) && ContainsString( iisres, "The remote procedure call failed" ) && ContainsString( iisres, "<title>Error" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

