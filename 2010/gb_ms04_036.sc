if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100608" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_cve_id( "CVE-2004-0574" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-26 19:54:51 +0200 (Mon, 26 Apr 2010)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Windows NT NNTP Component Buffer Overflow" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "nntpserver_detect.sc" );
	script_require_ports( "Services/nntp", 119 );
	script_mandatory_keys( "nntp/detected" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-036" );
	script_tag( name: "solution", value: "Microsoft has released a bulletin that includes fixes to address this
  issue for supported versions of the operating system." );
	script_tag( name: "summary", value: "The Network News Transfer Protocol (NNTP) component of Microsoft
  Windows NT Server 4.0, Windows 2000 Server, Windows Server 2003,
  Exchange 2000 Server, and Exchange Server 2003 allows remote attackers
  to execute arbitrary code via XPAT patterns, possibly related to
  improper length validation and an unchecked buffer, leading to
  off-by-one and heap-based buffer overflows." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("nntp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = nntp_get_port( default: 119 );
banner = get_kb_item( "nntp/banner/" + port );
if(!banner || !ContainsString( banner, "200 NNTP Service" )){
	exit( 0 );
}
version = eregmatch( pattern: "^200 NNTP Service .* Version: ([0-9.]+)", string: banner );
if(!version[1]){
	exit( 0 );
}
VULN = FALSE;
if( IsMatchRegexp( version[1], "^5\\.5\\." ) ){
	if(version_is_less( version: version[1], test_version: "5.5.1877.79" )){
		VULN = TRUE;
	}
}
else {
	if( IsMatchRegexp( version[1], "^5\\.0\\." ) ){
		if(version_is_less( version: version[1], test_version: "5.0.2195.6972" )){
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( version[1], "^6\\.0\\." )){
			if(version_is_less( version: version[1], test_version: "6.0.3790.206" )){
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version[1], fixed_version: "See referenced vendor advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

