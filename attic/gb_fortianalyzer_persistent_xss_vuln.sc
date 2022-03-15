if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809262" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_cve_id( "CVE-2016-3196" );
	script_bugtraq_id( 92265 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-09-21 10:02:40 +0530 (Wed, 21 Sep 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fortinet FortiAnalyzer Persistent XSS Vulnerability (FG-IR-16-014)" );
	script_tag( name: "summary", value: "Fortinet Fortianalyzer is prone to a persistent cross-site
  scripting (XSS) vulnerability.

  This VT has been replaced by the VT 'Fortinet FortiAnalyzer Persistent XSS Vulnerability
  (FG-IR-16-014)' (OID: 1.3.6.1.4.1.25623.1.0.105815)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists When a low privileged user uploads images in the
  report section, the filenames are not properly sanitized." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated users to
  inject arbitrary web script." );
	script_tag( name: "affected", value: "Fortinet FortiAnalyzer version 5.0.0 through 5.0.11 and 5.2.0
  through 5.2.5." );
	script_tag( name: "solution", value: "Update to version 5.0.12, 5.2.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-014" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

