if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101005" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-03-15 21:09:08 +0100 (Sun, 15 Mar 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043" );
	script_name( "Microsoft Security Bulletin MS07-040" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "find_service.sc", "remote-detect-MSdotNET-version.sc" );
	script_mandatory_keys( "dotNET/version" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-040" );
	script_tag( name: "solution", value: "Microsoft has released an update to correct this issue,
  please see the reference for more information." );
	script_tag( name: "summary", value: "Microsoft .NET is affected by multiples criticals vulnerabilities.
  Two of these vulnerabilities could allow remote code execution on client systems with .NET Framework installed,
  and one could allow information disclosure on Web servers running ASP.NET." );
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
dotnetversion["1.0"] = revcomp( a: dotnet, b: "1.0.3705.6060" );
dotnetversion["1.1"] = revcomp( a: dotnet, b: "1.1.4332.2407" );
dotnetversion["2.0"] = revcomp( a: dotnet, b: "2.0.50727.832" );
for version in dotnetversion {
	if(version == -1){
		report = "Missing MS07-040 patch, detected Microsoft .Net Framework version: " + dotnet;
		security_message( port: port, data: report );
	}
}
exit( 99 );

