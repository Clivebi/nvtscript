if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850252" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-13 17:02:02 +0530 (Thu, 13 Dec 2012)" );
	script_cve_id( "CVE-2012-2111" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:0583-1" );
	script_name( "openSUSE: Security Advisory for update (openSUSE-SU-2012:0583-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.4|openSUSE12\\.1)" );
	script_tag( name: "affected", value: "update on openSUSE 12.1, openSUSE 11.4" );
	script_tag( name: "insight", value: "- docs-xml: fix default name resolve order (bso#7564).

  - s3-aio-fork: Fix a segfault in vfs_aio_fork (bso#8836).

  - docs: remove whitespace in example samba.ldif (bso#8789).

  - s3-smbd: move print_backend_init() behind
  init_system_info() (bso#8845).

  - s3-docs: Prepend '/' to filename argument (bso#8826).

  - Restrict self granting privileges where security=ads for
  Samba post-3.3.16, CVE-2012-2111 (bnc#757576)." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "ldapsmb", rpm: "ldapsmb~1.34b~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~1.0.2~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1", rpm: "libldb1~1.0.2~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-debuginfo", rpm: "libldb1-debuginfo~1.0.2~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi-devel", rpm: "libnetapi-devel~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0", rpm: "libnetapi0~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-debuginfo", rpm: "libnetapi0-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo", rpm: "libsmbclient0-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbsharemodes-devel", rpm: "libsmbsharemodes-devel~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbsharemodes0", rpm: "libsmbsharemodes0~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbsharemodes0-debuginfo", rpm: "libsmbsharemodes0-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc-devel", rpm: "libtalloc-devel~2.0.5~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2", rpm: "libtalloc2~2.0.5~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-debuginfo", rpm: "libtalloc2-debuginfo~2.0.5~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb-devel", rpm: "libtdb-devel~1.2.9~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1", rpm: "libtdb1~1.2.9~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-debuginfo", rpm: "libtdb1-debuginfo~1.2.9~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-devel", rpm: "libtevent-devel~0.9.11~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0", rpm: "libtevent0~0.9.11~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-debuginfo", rpm: "libtevent0-debuginfo~0.9.11~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient-devel", rpm: "libwbclient-devel~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo", rpm: "libwbclient0-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo", rpm: "samba-client-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo", rpm: "samba-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debugsource", rpm: "samba-debugsource~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-devel", rpm: "samba-devel~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb-printing", rpm: "samba-krb-printing~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb-printing-debuginfo", rpm: "samba-krb-printing-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo", rpm: "samba-winbind-debuginfo~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-32bit", rpm: "libldb1-32bit~1.0.2~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-debuginfo-32bit", rpm: "libldb1-debuginfo-32bit~1.0.2~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo-32bit", rpm: "libsmbclient0-debuginfo-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-32bit", rpm: "libtalloc2-32bit~2.0.5~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-debuginfo-32bit", rpm: "libtalloc2-debuginfo-32bit~2.0.5~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-32bit", rpm: "libtdb1-32bit~1.2.9~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-debuginfo-32bit", rpm: "libtdb1-debuginfo-32bit~1.2.9~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-32bit", rpm: "libtevent0-32bit~0.9.11~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-debuginfo-32bit", rpm: "libtevent0-debuginfo-32bit~0.9.11~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo-32bit", rpm: "libwbclient0-debuginfo-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-32bit", rpm: "samba-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo-32bit", rpm: "samba-client-debuginfo-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo-32bit", rpm: "samba-debuginfo-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo-32bit", rpm: "samba-winbind-debuginfo-32bit~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-debuginfo-x86", rpm: "libldb1-debuginfo-x86~1.0.2~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-x86", rpm: "libldb1-x86~1.0.2~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo-x86", rpm: "libsmbclient0-debuginfo-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-x86", rpm: "libsmbclient0-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-debuginfo-x86", rpm: "libtalloc2-debuginfo-x86~2.0.5~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-x86", rpm: "libtalloc2-x86~2.0.5~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-debuginfo-x86", rpm: "libtdb1-debuginfo-x86~1.2.9~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-x86", rpm: "libtdb1-x86~1.2.9~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-debuginfo-x86", rpm: "libtevent0-debuginfo-x86~0.9.11~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-x86", rpm: "libtevent0-x86~0.9.11~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo-x86", rpm: "libwbclient0-debuginfo-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-x86", rpm: "libwbclient0-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo-x86", rpm: "samba-client-debuginfo-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-x86", rpm: "samba-client-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo-x86", rpm: "samba-debuginfo-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo-x86", rpm: "samba-winbind-debuginfo-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-x86", rpm: "samba-winbind-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-x86", rpm: "samba-x86~3.6.3~115.1", rls: "openSUSE11.4" ) )){
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
if(release == "openSUSE12.1"){
	if(!isnull( res = isrpmvuln( pkg: "ldapsmb", rpm: "ldapsmb~1.34b~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~1.0.2~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1", rpm: "libldb1~1.0.2~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-debuginfo", rpm: "libldb1-debuginfo~1.0.2~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi-devel", rpm: "libnetapi-devel~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0", rpm: "libnetapi0~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetapi0-debuginfo", rpm: "libnetapi0-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo", rpm: "libsmbclient0-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbsharemodes-devel", rpm: "libsmbsharemodes-devel~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbsharemodes0", rpm: "libsmbsharemodes0~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbsharemodes0-debuginfo", rpm: "libsmbsharemodes0-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc-devel", rpm: "libtalloc-devel~2.0.5~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2", rpm: "libtalloc2~2.0.5~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-debuginfo", rpm: "libtalloc2-debuginfo~2.0.5~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb-devel", rpm: "libtdb-devel~1.2.9~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1", rpm: "libtdb1~1.2.9~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-debuginfo", rpm: "libtdb1-debuginfo~1.2.9~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent-devel", rpm: "libtevent-devel~0.9.11~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0", rpm: "libtevent0~0.9.11~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-debuginfo", rpm: "libtevent0-debuginfo~0.9.11~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient-devel", rpm: "libwbclient-devel~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo", rpm: "libwbclient0-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo", rpm: "samba-client-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo", rpm: "samba-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debugsource", rpm: "samba-debugsource~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-devel", rpm: "samba-devel~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb-printing", rpm: "samba-krb-printing~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb-printing-debuginfo", rpm: "samba-krb-printing-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo", rpm: "samba-winbind-debuginfo~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-32bit", rpm: "libldb1-32bit~1.0.2~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-debuginfo-32bit", rpm: "libldb1-debuginfo-32bit~1.0.2~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo-32bit", rpm: "libsmbclient0-debuginfo-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-32bit", rpm: "libtalloc2-32bit~2.0.5~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-debuginfo-32bit", rpm: "libtalloc2-debuginfo-32bit~2.0.5~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-32bit", rpm: "libtdb1-32bit~1.2.9~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-debuginfo-32bit", rpm: "libtdb1-debuginfo-32bit~1.2.9~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-32bit", rpm: "libtevent0-32bit~0.9.11~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-debuginfo-32bit", rpm: "libtevent0-debuginfo-32bit~0.9.11~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo-32bit", rpm: "libwbclient0-debuginfo-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-32bit", rpm: "samba-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo-32bit", rpm: "samba-client-debuginfo-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo-32bit", rpm: "samba-debuginfo-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo-32bit", rpm: "samba-winbind-debuginfo-32bit~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-debuginfo-x86", rpm: "libldb1-debuginfo-x86~1.0.2~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-x86", rpm: "libldb1-x86~1.0.2~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-debuginfo-x86", rpm: "libsmbclient0-debuginfo-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-x86", rpm: "libsmbclient0-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-debuginfo-x86", rpm: "libtalloc2-debuginfo-x86~2.0.5~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-x86", rpm: "libtalloc2-x86~2.0.5~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-debuginfo-x86", rpm: "libtdb1-debuginfo-x86~1.2.9~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-x86", rpm: "libtdb1-x86~1.2.9~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-debuginfo-x86", rpm: "libtevent0-debuginfo-x86~0.9.11~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-x86", rpm: "libtevent0-x86~0.9.11~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-debuginfo-x86", rpm: "libwbclient0-debuginfo-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-x86", rpm: "libwbclient0-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-debuginfo-x86", rpm: "samba-client-debuginfo-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-x86", rpm: "samba-client-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-debuginfo-x86", rpm: "samba-debuginfo-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-debuginfo-x86", rpm: "samba-winbind-debuginfo-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-x86", rpm: "samba-winbind-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-x86", rpm: "samba-x86~3.6.3~34.12.1", rls: "openSUSE12.1" ) )){
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

