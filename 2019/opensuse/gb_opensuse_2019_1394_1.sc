if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852493" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-11234", "CVE-2019-11235" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-13 18:29:00 +0000 (Mon, 13 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-14 02:00:50 +0000 (Tue, 14 May 2019)" );
	script_name( "openSUSE: Security Advisory for freeradius-server (openSUSE-SU-2019:1394-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1394-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00032.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeradius-server'
  package(s) announced via the openSUSE-SU-2019:1394-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for freeradius-server fixes the following issues:

  Security issues fixed:

  - CVE-2019-11235: Fixed an authentication bypass related to the EAP-PWD
  Commit frame and insufficient validation of elliptic curve points
  (bsc#1132549).

  - CVE-2019-11234: Fixed an authentication bypass caused by reflecting
  privous values back to the server (bsc#1132664).

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1394=1" );
	script_tag( name: "affected", value: "'freeradius-server' package(s) on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server", rpm: "freeradius-server~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-debuginfo", rpm: "freeradius-server-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-debugsource", rpm: "freeradius-server-debugsource~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-devel", rpm: "freeradius-server-devel~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-doc", rpm: "freeradius-server-doc~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-krb5", rpm: "freeradius-server-krb5~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-krb5-debuginfo", rpm: "freeradius-server-krb5-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-ldap", rpm: "freeradius-server-ldap~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-ldap-debuginfo", rpm: "freeradius-server-ldap-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-libs", rpm: "freeradius-server-libs~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-libs-debuginfo", rpm: "freeradius-server-libs-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-mysql", rpm: "freeradius-server-mysql~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-mysql-debuginfo", rpm: "freeradius-server-mysql-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-perl", rpm: "freeradius-server-perl~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-perl-debuginfo", rpm: "freeradius-server-perl-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-postgresql", rpm: "freeradius-server-postgresql~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-postgresql-debuginfo", rpm: "freeradius-server-postgresql-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-python", rpm: "freeradius-server-python~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-python-debuginfo", rpm: "freeradius-server-python-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-sqlite", rpm: "freeradius-server-sqlite~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-sqlite-debuginfo", rpm: "freeradius-server-sqlite-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-utils", rpm: "freeradius-server-utils~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-utils-debuginfo", rpm: "freeradius-server-utils-debuginfo~3.0.15~9.1", rls: "openSUSELeap42.3" ) )){
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

