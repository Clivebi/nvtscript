if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103630" );
	script_bugtraq_id( 57038 );
	script_cve_id( "CVE-2012-0428", "CVE-2012-0429", "CVE-2012-0430", "CVE-2012-0432" );
	script_version( "2020-06-08T10:12:14+0000" );
	script_name( "Novell eDirectory Multiple Security Vulnerabilities" );
	script_tag( name: "last_modification", value: "2020-06-08 10:12:14 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2013-01-02 11:38:11 +0100 (Wed, 02 Jan 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "novell_edirectory_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "eDirectory/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57038" );
	script_tag( name: "solution", value: "An update is available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "Novell eDirectory is prone to following multiple remote
  vulnerabilities:

  1. A cross-site scripting vulnerability

  2. A denial-of-service vulnerability

  3. An information-disclosure vulnerability

  4. A stack-based buffer-overflow vulnerability" );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of
  the affected site, steal cookie-based authentication credentials,
  disclose sensitive information, execute arbitrary code, cause a denial-of-
  service condition. Other attacks are possible." );
	script_tag( name: "affected", value: "Novell eDirectory versions prior to 8.8.7.2 and 8.8.6.7 are
  vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:novell:edirectory",
	 "cpe:/a:netiq:edirectory" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!major = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(!sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" )){
	sp = "0";
}
revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string: revision, find: ".", replace: "" );
instvers = major;
if(sp > 0){
	instvers += " SP" + sp;
}
if(IsMatchRegexp( major, "^8\\.8" )){
	if(!sp || sp < 6){
		hole = TRUE;
	}
	if(sp == 6 && ( !revision || revision < 20608 )){
		hole = TRUE;
	}
	if(sp == 7 && ( !revision || revision < 20703 )){
		hole = TRUE;
	}
}
if(hole){
	report = report_fixed_ver( installed_version: instvers, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

