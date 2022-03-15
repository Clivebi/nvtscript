if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105361" );
	script_version( "2021-05-07T09:35:29+0000" );
	script_tag( name: "last_modification", value: "2021-05-07 09:35:29 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2015-09-18 14:39:37 +0200 (Fri, 18 Sep 2015)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2015-4736" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "F5 BIG-IP - Java vulnerability CVE-2015-4736" );
	script_category( ACT_GATHER_INFO );
	script_family( "F5 Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_tag( name: "summary", value: "The remote host is missing a security patch.

  This VT was deprecated as the vendor updated the referenced advisory stating that BIG-IP is not
  vulnerable." );
	script_tag( name: "insight", value: "Unspecified vulnerability in Oracle Java SE 7u80 and 8u45 allows
  remote attackers to affect confidentiality, integrity, and availability via unknown vectors
  related to Deployment. (CVE-2015-4736)" );
	script_tag( name: "impact", value: "Confidentiality, integrity, and availability may be affected when
  exploited by attackers. However, affected F5 products that contain the vulnerable software
  component do not use them in a way that exposes this vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "No solution is required.

  Note: The vendor updated the referenced advisory stating that BIG-IP is not vulnerable." );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K17170" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

