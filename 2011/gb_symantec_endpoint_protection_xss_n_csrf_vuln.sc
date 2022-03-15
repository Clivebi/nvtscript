if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802242" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)" );
	script_cve_id( "CVE-2011-0550", "CVE-2011-0551" );
	script_bugtraq_id( 48231, 49101 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Symantec Endpoint Protection Manager XSS and CSRF Vulnerabilities" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Symantec/Endpoint/Protection" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site." );
	script_tag( name: "affected", value: "Symantec Endpoint Protection (SEP) version 11.0.600x through 11.0.6300" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Input appended to the URL after /console/apps/sepm is not properly
    sanitised before being returned to the user.

  - Input passed via the 'token' parameter to portal/Help.jsp is not properly
    sanitised before being returned to the user.

  - The portal application allows users to perform certain actions via HTTP
    requests without performing any validity checks to verify the requests." );
	script_tag( name: "solution", value: "Upgrade to Symantec Endpoint Protection (SEP) version 11.0.7000 RU7 or
  later." );
	script_tag( name: "summary", value: "This host is installed with Symantec Endpoint Protection Manager
  and is prone to cross site scripting and cross site request forgery
  vulnerabilities." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43662" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1025919" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/69136" );
	script_xref( name: "URL", value: "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110810_00" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.symantec.com/business/endpoint-protection" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "Symantec/Endpoint/Protection" );
if(version){
	if(version_in_range( version: version, test_version: "11.0.600", test_version2: "11.0.6300" )){
		report = report_fixed_ver( installed_version: version, vulnerable_range: "11.0.600 - 11.0.6300" );
		security_message( port: 0, data: report );
	}
}

