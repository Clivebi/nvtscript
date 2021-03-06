if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122940" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:24:56 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Oracle Linux Local Check: ELSA-2016-0612" );
	script_tag( name: "insight", value: "ELSA-2016-0612 -  samba and samba4 security, bug fix, and enhancement update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2016-0612" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2016-0612.html" );
	script_cve_id( "CVE-2015-5370", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118", "CVE-2016-2110", "CVE-2016-2113", "CVE-2016-2114" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-27 17:17:00 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux(7|6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Oracle Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "OracleLinux7"){
	if(( res = isrpmvuln( pkg: "ctdb", rpm: "ctdb~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ctdb-devel", rpm: "ctdb-devel~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ctdb-tests", rpm: "ctdb-tests~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-admintools", rpm: "ipa-admintools~4.2.0~15.0.1.el7_2.6.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-client", rpm: "ipa-client~4.2.0~15.0.1.el7_2.6.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-python", rpm: "ipa-python~4.2.0~15.0.1.el7_2.6.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server", rpm: "ipa-server~4.2.0~15.0.1.el7_2.6.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server-dns", rpm: "ipa-server-dns~4.2.0~15.0.1.el7_2.6.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server-trust-ad", rpm: "ipa-server-trust-ad~4.2.0~15.0.1.el7_2.6.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ldb-tools", rpm: "ldb-tools~1.1.25~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libldb", rpm: "libldb~1.1.25~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~1.1.25~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtalloc", rpm: "libtalloc~2.1.5~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtalloc-devel", rpm: "libtalloc-devel~2.1.5~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtdb", rpm: "libtdb~1.3.8~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtdb-devel", rpm: "libtdb-devel~1.3.8~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtevent", rpm: "libtevent~0.9.26~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtevent-devel", rpm: "libtevent-devel~0.9.26~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwbclient-devel", rpm: "libwbclient-devel~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange", rpm: "openchange~2.0~10.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange-client", rpm: "openchange-client~2.0~10.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange-devel", rpm: "openchange-devel~2.0~10.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange-devel-docs", rpm: "openchange-devel-docs~2.0~10.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pyldb", rpm: "pyldb~1.1.25~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pyldb-devel", rpm: "pyldb-devel~1.1.25~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pytalloc", rpm: "pytalloc~2.1.5~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pytalloc-devel", rpm: "pytalloc-devel~2.1.5~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-tdb", rpm: "python-tdb~1.3.8~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-tevent", rpm: "python-tevent~0.9.26~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client-libs", rpm: "samba-client-libs~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common-libs", rpm: "samba-common-libs~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-dc", rpm: "samba-dc~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-dc-libs", rpm: "samba-dc-libs~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-devel", rpm: "samba-devel~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-pidl", rpm: "samba-pidl~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-python", rpm: "samba-python~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test", rpm: "samba-test~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test-devel", rpm: "samba-test-devel~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test-libs", rpm: "samba-test-libs~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-vfs-glusterfs", rpm: "samba-vfs-glusterfs~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-krb5-locator", rpm: "samba-winbind-krb5-locator~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-modules", rpm: "samba-winbind-modules~4.2.10~6.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tdb-tools", rpm: "tdb-tools~1.3.8~1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "ipa-admintools", rpm: "ipa-admintools~3.0.0~47.el6_7.2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-client", rpm: "ipa-client~3.0.0~47.el6_7.2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-python", rpm: "ipa-python~3.0.0~47.el6_7.2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server", rpm: "ipa-server~3.0.0~47.el6_7.2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server-selinux", rpm: "ipa-server-selinux~3.0.0~47.el6_7.2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server-trust-ad", rpm: "ipa-server-trust-ad~3.0.0~47.el6_7.2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ldb-tools", rpm: "ldb-tools~1.1.25~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libldb", rpm: "libldb~1.1.25~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~1.1.25~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtalloc", rpm: "libtalloc~2.1.5~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtalloc-devel", rpm: "libtalloc-devel~2.1.5~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtdb", rpm: "libtdb~1.3.8~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtdb-devel", rpm: "libtdb-devel~1.3.8~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtevent", rpm: "libtevent~0.9.26~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtevent-devel", rpm: "libtevent-devel~0.9.26~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange", rpm: "openchange~1.0~7.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange-client", rpm: "openchange-client~1.0~7.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange-devel", rpm: "openchange-devel~1.0~7.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openchange-devel-docs", rpm: "openchange-devel-docs~1.0~7.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pyldb", rpm: "pyldb~1.1.25~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pyldb-devel", rpm: "pyldb-devel~1.1.25~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pytalloc", rpm: "pytalloc~2.1.5~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pytalloc-devel", rpm: "pytalloc-devel~2.1.5~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-tdb", rpm: "python-tdb~1.3.8~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-tevent", rpm: "python-tevent~0.9.26~2.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4", rpm: "samba4~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-client", rpm: "samba4-client~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-common", rpm: "samba4-common~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-dc", rpm: "samba4-dc~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-dc-libs", rpm: "samba4-dc-libs~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-devel", rpm: "samba4-devel~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-libs", rpm: "samba4-libs~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-pidl", rpm: "samba4-pidl~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-python", rpm: "samba4-python~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-test", rpm: "samba4-test~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-winbind", rpm: "samba4-winbind~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-winbind-clients", rpm: "samba4-winbind-clients~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-winbind-krb5-locator", rpm: "samba4-winbind-krb5-locator~4.2.10~6.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tdb-tools", rpm: "tdb-tools~1.3.8~1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

