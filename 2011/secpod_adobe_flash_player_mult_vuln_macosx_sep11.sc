if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902740" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)" );
	script_cve_id( "CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2428", "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444" );
	script_bugtraq_id( 49714, 49715, 49716, 49718, 49717, 49710 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities September-2011 (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service." );
	script_tag( name: "affected", value: "Adobe Flash Player versions prior to 10.3.183.10 on Mac OS X." );
	script_tag( name: "insight", value: "The flaws are due to

  - Stack-based buffer overflow in the ActionScript Virtual Machine (AVM)
    component, allows remote attackers to execute arbitrary code via
    unspecified vectors.

  - logic error issue, allows attackers to execute arbitrary code or cause a
    denial of service (browser crash) via unspecified vectors.

  - security control bypass, allows attackers to bypass intended access
    restrictions and obtain sensitive information via unspecified vectors

  - logic error vulnerability, allows remote attackers to execute arbitrary
    code via crafted streaming media

  - Cross-site scripting (XSS) vulnerability, allows remote attackers to
    inject arbitrary web script or HTML via a crafted URL." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.3.183.10 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-26.html" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Adobe/Flash/Player/MacOSX/Version" );
if(!vers){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "10.3.183.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.183.10" );
	security_message( port: 0, data: report );
}

