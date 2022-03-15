if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100692" );
	script_version( "2020-06-08T10:12:14+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 10:12:14 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-06-24 12:53:20 +0200 (Thu, 24 Jun 2010)" );
	script_bugtraq_id( 40480, 40485 );
	script_cve_id( "CVE-2010-1929", "CVE-2010-1930" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "Novell iManager < 2.7.4 Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40480" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40485" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/novell-imanager-buffer-overflow-off-by-one-vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "novell_imanager_detect.sc" );
	script_mandatory_keys( "novellimanager/installed" );
	script_tag( name: "summary", value: "Novell iManager is prone to multiple Vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws and impact exists:

  - A stack-based buffer-overflow vulnerability because it fails to perform adequate boundary checks on
    user-supplied data. Attackers may exploit this issue to execute arbitrary code with SYSTEM-level privileges.
    Successful exploits will completely compromise affected computers. Failed exploit attempts will result in a
    denial-of-service condition.

  - A denial-of-service vulnerability due to an off-by-one error. Attackers may exploit this issue to crash the
   affected application, denying service to legitimate users." );
	script_tag( name: "affected", value: "Versions prior to Novell iManager 2.7.4 are vulnerable." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:novell:imanager",
	 "cpe:/a:netiq:imanager" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!version = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.7.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

