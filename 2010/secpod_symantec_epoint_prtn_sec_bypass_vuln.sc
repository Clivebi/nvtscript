if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902124" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0106" );
	script_bugtraq_id( 38219 );
	script_name( "Symantec Endpoint Protection Scan Bypass Vulnerability" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Symantec/Endpoint/Protection" );
	script_tag( name: "affected", value: "Symantec Endpoint Protection 11.x" );
	script_tag( name: "insight", value: "Issue is caused by an unspecified error in the 'on-demand' scanning feature
when another entity denies read access to the AntiVirus while the Tamper
protection is disabled." );
	script_tag( name: "summary", value: "The host is installed with Symantec Endpoint Protection and is
possible to bypass security scan." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "impact", value: "Successful exploitation will let attacker to pass sufficient specific events
to the application to bypass an on-demand scan." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38653" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0410" );
	script_xref( name: "URL", value: "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100217_00" );
	exit( 0 );
}
sepVer = get_kb_item( "Symantec/Endpoint/Protection" );
if(!isnull( sepVer ) && ( IsMatchRegexp( sepVer, "^11.*" ) )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

