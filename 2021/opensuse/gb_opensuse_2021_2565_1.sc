if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854028" );
	script_version( "2021-08-03T06:52:21+0000" );
	script_cve_id( "CVE-2010-2322" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-03 06:52:21 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-30 03:02:06 +0000 (Fri, 30 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for fastjar (openSUSE-SU-2021:2565-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2565-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OHWHBBR2CBRHE7HR6PAPJLGHP3QCHYHS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fastjar'
  package(s) announced via the openSUSE-SU-2021:2565-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for fastjar fixes the following issues:

  - CVE-2010-2322: Fixed a directory traversal vulnerabilities. (bsc#1188517)" );
	script_tag( name: "affected", value: "'fastjar' package(s) on openSUSE Leap 15.3." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "fastjar", rpm: "fastjar~0.98~3.6.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fastjar-debuginfo", rpm: "fastjar-debuginfo~0.98~3.6.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fastjar-debugsource", rpm: "fastjar-debugsource~0.98~3.6.2", rls: "openSUSELeap15.3" ) )){
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

