if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852764" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-10218", "CVE-2019-14833", "CVE-2019-14847" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)" );
	script_tag( name: "creation_date", value: "2019-11-10 03:00:51 +0000 (Sun, 10 Nov 2019)" );
	script_name( "openSUSE: Security Advisory for samba (openSUSE-SU-2019:2458-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2458-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00015.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the openSUSE-SU-2019:2458-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for samba fixes the following issues:

  Security issues fixed:

  - CVE-2019-14847: User with 'get changes' permission can crash AD DC LDAP
  server via dirsync (bsc#1154598).

  - CVE-2019-10218: Client code can return filenames containing path
  separators (bsc#1144902).

  - CVE-2019-14833: Fixed Accent with 'check script password' where the
  Samba AD DC check password script does not receive the full password
  (bsc#1154289).

  Other issues fixed:

  - Fix vfs_ceph realpath (bsc#1134452).

  - MacOS credit accounting breaks with async SESSION SETUP (bsc#1125601).

  - Mac OS X SMB2 implementation sees Input/output error or Resource
  temporarily unavailable and drops connection

  - Explicitly enable libcephfs POSIX ACL support (bsc#1130245).

  - Fix vfs_ceph ftruncate and fallocate handling (bsc#1127153). This update
  was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2458=1" );
	script_tag( name: "affected", value: "'samba' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "ctdb", rpm: "ctdb~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ctdb-debuginfo", rpm: "ctdb-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ctdb-pcp-pmda", rpm: "ctdb-pcp-pmda~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ctdb-pcp-pmda-debuginfo", rpm: "ctdb-pcp-pmda-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ctdb-tests", rpm: "ctdb-tests~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ctdb-tests-debuginfo", rpm: "ctdb-tests-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0", rpm: "libdcerpc-binding0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-debuginfo", rpm: "libdcerpc-binding0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-devel", rpm: "libdcerpc-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-samr-devel", rpm: "libdcerpc-samr-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-samr0", rpm: "libdcerpc-samr0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-samr0-debuginfo", rpm: "libdcerpc-samr0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0", rpm: "libdcerpc0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-debuginfo", rpm: "libdcerpc0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-devel", rpm: "libndr-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac-devel", rpm: "libndr-krb5pac-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0", rpm: "libndr-krb5pac0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-debuginfo", rpm: "libndr-krb5pac0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt-devel", rpm: "libndr-nbt-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0", rpm: "libndr-nbt0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-debuginfo", rpm: "libndr-nbt0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard-devel", rpm: "libndr-standard-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0", rpm: "libndr-standard0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-debuginfo", rpm: "libndr-standard0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0", rpm: "libndr0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-debuginfo", rpm: "libndr0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi-devel", rpm: "libnetapi-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0", rpm: "libnetapi0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-debuginfo", rpm: "libnetapi0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials-devel", rpm: "libsamba-credentials-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0", rpm: "libsamba-credentials0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-debuginfo", rpm: "libsamba-credentials0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-errors-devel", rpm: "libsamba-errors-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-errors0", rpm: "libsamba-errors0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-errors0-debuginfo", rpm: "libsamba-errors0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig-devel", rpm: "libsamba-hostconfig-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0", rpm: "libsamba-hostconfig0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-debuginfo", rpm: "libsamba-hostconfig0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb-devel", rpm: "libsamba-passdb-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0", rpm: "libsamba-passdb0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-debuginfo", rpm: "libsamba-passdb0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-policy-devel", rpm: "libsamba-policy-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-policy0", rpm: "libsamba-policy0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-policy0-debuginfo", rpm: "libsamba-policy0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util-devel", rpm: "libsamba-util-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0", rpm: "libsamba-util0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-debuginfo", rpm: "libsamba-util0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb-devel", rpm: "libsamdb-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0", rpm: "libsamdb0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-debuginfo", rpm: "libsamdb0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo", rpm: "libsmbclient0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf-devel", rpm: "libsmbconf-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0", rpm: "libsmbconf0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-debuginfo", rpm: "libsmbconf0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap-devel", rpm: "libsmbldap-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap2", rpm: "libsmbldap2~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap2-debuginfo", rpm: "libsmbldap2-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util-devel", rpm: "libtevent-util-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0", rpm: "libtevent-util0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-debuginfo", rpm: "libtevent-util0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient-devel", rpm: "libwbclient-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo", rpm: "libwbclient0-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo", rpm: "samba-client-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-core-devel", rpm: "samba-core-devel~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo", rpm: "samba-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debugsource", rpm: "samba-debugsource~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-dsdb-modules", rpm: "samba-dsdb-modules~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-dsdb-modules-debuginfo", rpm: "samba-dsdb-modules-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-kdc", rpm: "samba-kdc~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-kdc-debuginfo", rpm: "samba-kdc-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-debuginfo", rpm: "samba-libs-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-pidl", rpm: "samba-pidl~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-python", rpm: "samba-python~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-python-debuginfo", rpm: "samba-python-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-test", rpm: "samba-test~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-test-debuginfo", rpm: "samba-test-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo", rpm: "samba-winbind-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-32bit", rpm: "libdcerpc-binding0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-32bit-debuginfo", rpm: "libdcerpc-binding0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-samr0-32bit", rpm: "libdcerpc-samr0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-samr0-32bit-debuginfo", rpm: "libdcerpc-samr0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-32bit", rpm: "libdcerpc0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-32bit-debuginfo", rpm: "libdcerpc0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-32bit", rpm: "libndr-krb5pac0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-32bit-debuginfo", rpm: "libndr-krb5pac0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-32bit", rpm: "libndr-nbt0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-32bit-debuginfo", rpm: "libndr-nbt0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-32bit", rpm: "libndr-standard0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-32bit-debuginfo", rpm: "libndr-standard0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-32bit", rpm: "libndr0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-32bit-debuginfo", rpm: "libndr0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-32bit", rpm: "libnetapi0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-32bit-debuginfo", rpm: "libnetapi0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-32bit", rpm: "libsamba-credentials0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "<br>libsamba-credentials0-32bit-debuginfo", rpm: "<br>libsamba-credentials0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-errors0-32bit", rpm: "libsamba-errors0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-errors0-32bit-debuginfo", rpm: "libsamba-errors0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-32bit", rpm: "libsamba-hostconfig0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "<br>libsamba-hostconfig0-32bit-debuginfo", rpm: "<br>libsamba-hostconfig0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-32bit", rpm: "libsamba-passdb0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-32bit-debuginfo", rpm: "libsamba-passdb0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-policy0-32bit", rpm: "libsamba-policy0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-policy0-32bit-debuginfo", rpm: "libsamba-policy0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-32bit", rpm: "libsamba-util0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-32bit-debuginfo", rpm: "libsamba-util0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-32bit", rpm: "libsamdb0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-32bit-debuginfo", rpm: "libsamdb0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit-debuginfo", rpm: "libsmbclient0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-32bit", rpm: "libsmbconf0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-32bit-debuginfo", rpm: "libsmbconf0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap2-32bit", rpm: "libsmbldap2-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap2-32bit-debuginfo", rpm: "libsmbldap2-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-32bit", rpm: "libtevent-util0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-32bit-debuginfo", rpm: "libtevent-util0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit-debuginfo", rpm: "libwbclient0-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-ceph", rpm: "samba-ceph~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-ceph-debuginfo", rpm: "samba-ceph-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit-debuginfo", rpm: "samba-client-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-kdc-32bit", rpm: "samba-kdc-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-kdc-32bit-debuginfo", rpm: "samba-kdc-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-32bit", rpm: "samba-libs-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-32bit-debuginfo", rpm: "samba-libs-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit-debuginfo", rpm: "samba-winbind-32bit-debuginfo~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~4.7.11+git.186.d75219614c3~lp150.3.18.2", rls: "openSUSELeap15.0" ) )){
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

