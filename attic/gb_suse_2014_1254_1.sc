if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850676" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-09-18 10:31:31 +0200 (Fri, 18 Sep 2015)" );
	script_cve_id( "CVE-2014-6271", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for bash (openSUSE-SU-2014:1254-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory.

  This NVT has been deprecated because no proper information available
  from advisory link." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "bash was updated to fix command injection via environment variables.
  (CVE-2014-6271, CVE-2014-7169)

  Also a hardening patch was applied that only imports functions over
  BASH_FUNC_ prefixed environment variables.

  Also fixed: CVE-2014-7186, CVE-2014-7187: bad handling of HERE documents
  and for loop issue" );
	script_tag( name: "affected", value: "bash on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2014:1254-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	exit( 0 );
}
exit( 66 );

