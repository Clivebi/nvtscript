if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108625" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_cve_id( "CVE-2017-9793" );
	script_bugtraq_id( 100611 );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-28 06:34:39 +0000 (Wed, 28 Aug 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-12 21:15:00 +0000 (Mon, 12 Aug 2019)" );
	script_name( "Apache Struts DoS Vulnerability (S2-051) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/100611" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-051" );
	script_tag( name: "summary", value: "Apache Struts is prone to a Denial of Service (DoS)
  vulnerability in the Struts REST plugin.

  This VT has been merged into the VT 'Apache Struts DoS Vulnerability (S2-051)'
  (OID: 1.3.6.1.4.1.25623.1.0.108624)." );
	script_tag( name: "insight", value: "The REST Plugin is using outdated XStream library
  which is vulnerable and allow perform a DoS attack using malicious request with
  specially crafted XML payload." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause a DoS
  condition, denying service to legitimate users." );
	script_tag( name: "affected", value: "Apache Struts 2.1.6 through 2.3.33 and 2.5 through
  2.5.12." );
	script_tag( name: "solution", value: "Update to version 2.3.34, 2.5.13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

