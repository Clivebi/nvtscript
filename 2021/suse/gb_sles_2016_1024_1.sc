if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.1024.1" );
	script_cve_id( "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2115", "CVE-2016-2118" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-27 17:17:00 +0000 (Fri, 27 Sep 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:1024-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:1024-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20161024-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2016:1024-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "samba was updated to fix seven security issues.
These security issues were fixed:
- CVE-2015-5370: DCERPC server and client were vulnerable to DOS and MITM
 attacks (bsc#936862).
- CVE-2016-2110: A man-in-the-middle could have downgraded NTLMSSP
 authentication (bsc#973031).
- CVE-2016-2111: Domain controller netlogon member computer could have
 been spoofed (bsc#973032).
- CVE-2016-2112: LDAP conenctions were vulnerable to downgrade and MITM
 attack (bsc#973033).
- CVE-2016-2113: TLS certificate validation were missing (bsc#973034).
- CVE-2016-2115: Named pipe IPC were vulnerable to MITM attacks
 (bsc#973036).
- CVE-2016-2118: 'Badlock' DCERPC impersonation of authenticated account
 were possible (bsc#971965).
These non-security issues were fixed:
- bsc#974629: Fix samba.tests.messaging test and prevent potential tdb
 corruption by removing obsolete now invalid tdb_close call.
- bsc#973832: Obsolete libsmbsharemodes0 from samba-libs and
 libsmbsharemodes-devel from samba-core-devel.
- bsc#972197: Obsolete libsmbclient from libsmbclient0 and libpdb-devel
 from libsamba-passdb-devel while not providing it.
- Getting and setting Windows ACLs on symlinks can change permissions on
 link
- bsc#924519: Upgrade on-disk FSRVP server state to new version.
- bsc#968973: Only obsolete but do not provide gplv2/3 package names.
- bso#6482: s3:utils/smbget: Fix recursive download.
- bso#10489: s3: smbd: posix_acls: Fix check for setting u:g:o entry on a
 filesystem with no ACL support.
- bso#11643: docs: Add example for domain logins to smbspool man page.
- bso#11690: s3-client: Add a KRB5 wrapper for smbspool.
- bso#11708: loadparm: Fix memory leak issue.
- bso#11714: lib/tsocket: Work around sockets not supporting FIONREAD.
- bso#11719: ctdb-scripts: Drop use of 'smbcontrol winbindd ip-dropped
 ...'.
- bso#11727: s3:smbd:open: Skip redundant call to file_set_dosmode when
 creating a new file.
- bso#11732: param: Fix str_list_v3 to accept ',' again.
- bso#11740: Real memeory leak(buildup) issue in loadparm." );
	script_tag( name: "affected", value: "'samba' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise High Availability 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-32bit", rpm: "libdcerpc-binding0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0", rpm: "libdcerpc-binding0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-debuginfo-32bit", rpm: "libdcerpc-binding0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-debuginfo", rpm: "libdcerpc-binding0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-32bit", rpm: "libdcerpc0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0", rpm: "libdcerpc0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-debuginfo-32bit", rpm: "libdcerpc0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-debuginfo", rpm: "libdcerpc0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0-32bit", rpm: "libgensec0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0", rpm: "libgensec0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0-debuginfo-32bit", rpm: "libgensec0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0-debuginfo", rpm: "libgensec0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-32bit", rpm: "libndr-krb5pac0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0", rpm: "libndr-krb5pac0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-debuginfo-32bit", rpm: "libndr-krb5pac0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-debuginfo", rpm: "libndr-krb5pac0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-32bit", rpm: "libndr-nbt0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0", rpm: "libndr-nbt0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-debuginfo-32bit", rpm: "libndr-nbt0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-debuginfo", rpm: "libndr-nbt0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-32bit", rpm: "libndr-standard0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0", rpm: "libndr-standard0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-debuginfo-32bit", rpm: "libndr-standard0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-debuginfo", rpm: "libndr-standard0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-32bit", rpm: "libndr0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0", rpm: "libndr0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-debuginfo-32bit", rpm: "libndr0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-debuginfo", rpm: "libndr0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-32bit", rpm: "libnetapi0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0", rpm: "libnetapi0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-debuginfo-32bit", rpm: "libnetapi0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-debuginfo", rpm: "libnetapi0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libregistry0", rpm: "libregistry0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libregistry0-debuginfo", rpm: "libregistry0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-32bit", rpm: "libsamba-credentials0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0", rpm: "libsamba-credentials0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-debuginfo-32bit", rpm: "libsamba-credentials0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-debuginfo", rpm: "libsamba-credentials0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-32bit", rpm: "libsamba-hostconfig0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0", rpm: "libsamba-hostconfig0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-debuginfo-32bit", rpm: "libsamba-hostconfig0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-debuginfo", rpm: "libsamba-hostconfig0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-32bit", rpm: "libsamba-passdb0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0", rpm: "libsamba-passdb0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-debuginfo-32bit", rpm: "libsamba-passdb0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-debuginfo", rpm: "libsamba-passdb0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-32bit", rpm: "libsamba-util0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0", rpm: "libsamba-util0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-debuginfo-32bit", rpm: "libsamba-util0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-debuginfo", rpm: "libsamba-util0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-32bit", rpm: "libsamdb0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0", rpm: "libsamdb0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-debuginfo-32bit", rpm: "libsamdb0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-debuginfo", rpm: "libsamdb0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0-32bit", rpm: "libsmbclient-raw0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0", rpm: "libsmbclient-raw0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0-debuginfo-32bit", rpm: "libsmbclient-raw0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0-debuginfo", rpm: "libsmbclient-raw0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo-32bit", rpm: "libsmbclient0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo", rpm: "libsmbclient0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-32bit", rpm: "libsmbconf0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0", rpm: "libsmbconf0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-debuginfo-32bit", rpm: "libsmbconf0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-debuginfo", rpm: "libsmbconf0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0-32bit", rpm: "libsmbldap0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0", rpm: "libsmbldap0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0-debuginfo-32bit", rpm: "libsmbldap0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0-debuginfo", rpm: "libsmbldap0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-32bit", rpm: "libtevent-util0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0", rpm: "libtevent-util0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-debuginfo-32bit", rpm: "libtevent-util0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-debuginfo", rpm: "libtevent-util0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo-32bit", rpm: "libwbclient0-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo", rpm: "libwbclient0-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-32bit", rpm: "samba-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo-32bit", rpm: "samba-client-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo", rpm: "samba-client-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo-32bit", rpm: "samba-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo", rpm: "samba-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debugsource", rpm: "samba-debugsource~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-32bit", rpm: "samba-libs-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-debuginfo-32bit", rpm: "samba-libs-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-debuginfo", rpm: "samba-libs-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo-32bit", rpm: "samba-winbind-debuginfo-32bit~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo", rpm: "samba-winbind-debuginfo~4.2.4~16.1", rls: "SLES12.0SP1" ) )){
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

