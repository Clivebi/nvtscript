if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852646" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2017-7418", "CVE-2019-12815" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-09 02:01:01 +0000 (Fri, 09 Aug 2019)" );
	script_name( "openSUSE: Security Advisory for proftpd (openSUSE-SU-2019:1836-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1836-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'proftpd'
  package(s) announced via the openSUSE-SU-2019:1836-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for proftpd fixes the following issues:

  Security issues fixed:

  - CVE-2019-12815: Fixed arbitrary file copy in mod_copy that allowed for
  remote code execution and information disclosure without authentication
  (bnc#1142281).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1836=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1836=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1836=1" );
	script_tag( name: "affected", value: "'proftpd' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "proftpd", rpm: "proftpd~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-debuginfo", rpm: "proftpd-debuginfo~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-debugsource", rpm: "proftpd-debugsource~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-devel", rpm: "proftpd-devel~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-doc", rpm: "proftpd-doc~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-ldap", rpm: "proftpd-ldap~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-ldap-debuginfo", rpm: "proftpd-ldap-debuginfo~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-mysql", rpm: "proftpd-mysql~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-mysql-debuginfo", rpm: "proftpd-mysql-debuginfo~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-pgsql", rpm: "proftpd-pgsql~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-pgsql-debuginfo", rpm: "proftpd-pgsql-debuginfo~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-radius", rpm: "proftpd-radius~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-radius-debuginfo", rpm: "proftpd-radius-debuginfo~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-sqlite", rpm: "proftpd-sqlite~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-sqlite-debuginfo", rpm: "proftpd-sqlite-debuginfo~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "proftpd-lang", rpm: "proftpd-lang~1.3.5e~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

