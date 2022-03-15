if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2570.1" );
	script_cve_id( "CVE-2016-2119" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2570-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2570-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162570-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2016:2570-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for samba provides the following fix:
Following security issue was fixed:
- CVE-2016-2119: Prevent client-side SMB2 signing downgrade. (bsc#986869)
Also the following bugs were fixed:
- Fix possible ctdb crash when opening sockets with htons(IPPROTO_RAW).
 (bsc#969522)
- Honor smb.conf socket options in winbind. (bsc#975131)
- Fix ntlm-auth segmentation fault with squid. (bsc#986228)
- Implement new '--no-dns-updates' option in 'net ads' command.
 (bsc#991564)
- Fix population of ctdb sysconfig after source merge. (bsc#981566)" );
	script_tag( name: "affected", value: "'samba' package(s) on SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "ctdb", rpm: "ctdb~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ctdb-debuginfo", rpm: "ctdb-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-32bit", rpm: "libdcerpc-binding0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0", rpm: "libdcerpc-binding0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-debuginfo-32bit", rpm: "libdcerpc-binding0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc-binding0-debuginfo", rpm: "libdcerpc-binding0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-32bit", rpm: "libdcerpc0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0", rpm: "libdcerpc0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-debuginfo-32bit", rpm: "libdcerpc0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdcerpc0-debuginfo", rpm: "libdcerpc0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0-32bit", rpm: "libgensec0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0", rpm: "libgensec0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0-debuginfo-32bit", rpm: "libgensec0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgensec0-debuginfo", rpm: "libgensec0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-32bit", rpm: "libndr-krb5pac0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0", rpm: "libndr-krb5pac0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-debuginfo-32bit", rpm: "libndr-krb5pac0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-krb5pac0-debuginfo", rpm: "libndr-krb5pac0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-32bit", rpm: "libndr-nbt0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0", rpm: "libndr-nbt0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-debuginfo-32bit", rpm: "libndr-nbt0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-nbt0-debuginfo", rpm: "libndr-nbt0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-32bit", rpm: "libndr-standard0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0", rpm: "libndr-standard0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-debuginfo-32bit", rpm: "libndr-standard0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr-standard0-debuginfo", rpm: "libndr-standard0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-32bit", rpm: "libndr0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0", rpm: "libndr0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-debuginfo-32bit", rpm: "libndr0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libndr0-debuginfo", rpm: "libndr0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-32bit", rpm: "libnetapi0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0", rpm: "libnetapi0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-debuginfo-32bit", rpm: "libnetapi0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-debuginfo", rpm: "libnetapi0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libregistry0", rpm: "libregistry0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libregistry0-debuginfo", rpm: "libregistry0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-32bit", rpm: "libsamba-credentials0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0", rpm: "libsamba-credentials0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-debuginfo-32bit", rpm: "libsamba-credentials0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-credentials0-debuginfo", rpm: "libsamba-credentials0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-32bit", rpm: "libsamba-hostconfig0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0", rpm: "libsamba-hostconfig0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-debuginfo-32bit", rpm: "libsamba-hostconfig0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-hostconfig0-debuginfo", rpm: "libsamba-hostconfig0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-32bit", rpm: "libsamba-passdb0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0", rpm: "libsamba-passdb0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-debuginfo-32bit", rpm: "libsamba-passdb0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-passdb0-debuginfo", rpm: "libsamba-passdb0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-32bit", rpm: "libsamba-util0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0", rpm: "libsamba-util0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-debuginfo-32bit", rpm: "libsamba-util0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamba-util0-debuginfo", rpm: "libsamba-util0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-32bit", rpm: "libsamdb0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0", rpm: "libsamdb0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-debuginfo-32bit", rpm: "libsamdb0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsamdb0-debuginfo", rpm: "libsamdb0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0-32bit", rpm: "libsmbclient-raw0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0", rpm: "libsmbclient-raw0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0-debuginfo-32bit", rpm: "libsmbclient-raw0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-raw0-debuginfo", rpm: "libsmbclient-raw0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo-32bit", rpm: "libsmbclient0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo", rpm: "libsmbclient0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-32bit", rpm: "libsmbconf0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0", rpm: "libsmbconf0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-debuginfo-32bit", rpm: "libsmbconf0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbconf0-debuginfo", rpm: "libsmbconf0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0-32bit", rpm: "libsmbldap0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0", rpm: "libsmbldap0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0-debuginfo-32bit", rpm: "libsmbldap0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbldap0-debuginfo", rpm: "libsmbldap0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-32bit", rpm: "libtevent-util0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0", rpm: "libtevent-util0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-debuginfo-32bit", rpm: "libtevent-util0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-util0-debuginfo", rpm: "libtevent-util0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo-32bit", rpm: "libwbclient0-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo", rpm: "libwbclient0-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-32bit", rpm: "samba-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo-32bit", rpm: "samba-client-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo", rpm: "samba-client-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo-32bit", rpm: "samba-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo", rpm: "samba-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debugsource", rpm: "samba-debugsource~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-32bit", rpm: "samba-libs-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-debuginfo-32bit", rpm: "samba-libs-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs-debuginfo", rpm: "samba-libs-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo-32bit", rpm: "samba-winbind-debuginfo-32bit~4.2.4~18.27.9", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo", rpm: "samba-winbind-debuginfo~4.2.4~18.27.9", rls: "SLES12.0" ) )){
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

