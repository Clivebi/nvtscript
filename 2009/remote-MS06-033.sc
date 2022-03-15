if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101009" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-03-15 21:56:45 +0100 (Sun, 15 Mar 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 18920 );
	script_cve_id( "CVE-2006-1300" );
	script_name( "Microsoft Security Bulletin MS06-033" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "find_service.sc", "remote-detect-MSdotNET-version.sc" );
	script_mandatory_keys( "dotNET/version" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-033" );
	script_tag( name: "solution", value: "Microsoft has released an update to correct this issue,
  please see the reference for more information." );
	script_tag( name: "summary", value: "This Information Disclosure vulnerability could allow an
  attacker to bypass ASP.Net security and gain unauthorized access to objects in the
  Application folders explicitly by name." );
	script_tag( name: "impact", value: "this could be used to produce useful information that could
  be used to try to further compromise the affected system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
dotnet = get_kb_item( "dotNET/version" );
if(!dotnet){
	exit( 0 );
}
port = get_kb_item( "dotNET/port" );
if(revcomp( a: dotnet, b: "2.0.50727.101" ) == -1){
	report = "Missing MS06-033 patch, detected Microsoft .Net Framework version: " + dotnet;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

