if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107162" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-02 11:40:28 +0200 (Tue, 02 May 2017)" );
	script_cve_id( "CVE-2017-7126" );
	script_bugtraq_id( 97590 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-25 19:39:00 +0000 (Wed, 25 Oct 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Palo Alto Networks PAN-OS CVE-2017-7216 Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "Palo Alto Networks PAN-OS is prone to an information-disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Management Web Interface does not properly validate specific request parameters which can potentially allow for Information Disclosure." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive information that may aid in launching further attacks." );
	script_tag( name: "affected", value: "Palo Alto Networks PAN-OS 7.1.8 and prior versions are vulnerable" );
	script_tag( name: "solution", value: "Update to Paloaltonetworks PAN-OS 7.1.9." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/97590" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/80" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

