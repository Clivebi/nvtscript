if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811836" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2014-2730" );
	script_bugtraq_id( 78020 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2017-09-19 13:12:31 +0530 (Tue, 19 Sep 2017)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "Microsoft Office Outlook Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Microsoft Office Outlook
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the XML parser in Microsoft
  Office does not properly detect recursion during entity expansion." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (memory consumption and persistent
  application hang) via a crafted XML document." );
	script_tag( name: "affected", value: "- Microsoft Outlook 2007

  - Microsoft Outlook 2010

  - Microsoft Outlook 2013" );
	script_tag( name: "solution", value: "A workaround is to add a rule blocking
  XML DTD Entities ('<!ENTITY', case-insensitive) to your spam filter. Creating
  an Outlook rule to permanently delete messages containing '<!ENTITY' also
  mitigates the attack." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/531722/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Outlook/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
outlookVer = get_kb_item( "SMB/Office/Outlook/Version" );
if(outlookVer && IsMatchRegexp( outlookVer, "^(12|14|15)\\." )){
	report = report_fixed_ver( installed_version: outlookVer, fixed_version: "Mitigation" );
	security_message( data: report );
	exit( 0 );
}

