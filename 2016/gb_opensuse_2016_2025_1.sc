if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851378" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-08-11 05:38:38 +0200 (Thu, 11 Aug 2016)" );
	script_cve_id( "CVE-2013-4701", "CVE-2013-7073", "CVE-2014-3941" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for Typo3 (openSUSE-SU-2016:2025-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Important'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Important security fixes for vulnerabilities in typo3 which can be used
  for Cross-Site Scripting or Denial of Service attacks or for
  authentication bypassing." );
	script_tag( name: "affected", value: "Typo3 on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:2025-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "typo3-cms-4_5", rpm: "typo3-cms-4_5~4.5.40~2.7.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typo3-cms-4_7", rpm: "typo3-cms-4_7~4.7.20~3.3.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

