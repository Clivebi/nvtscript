if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818448" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-09 01:17:22 +0000 (Thu, 09 Sep 2021)" );
	script_name( "Fedora: Security Advisory for ntfs-3g (FEDORA-2021-4dd269a76c)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC35" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-4dd269a76c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PXX7NFDD25ZGUAUCBUDIY2723RIK7WJE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntfs-3g'
  package(s) announced via the FEDORA-2021-4dd269a76c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "NTFS-3G is a stable, open source, GPL licensed, POSIX, read/write NTFS
driver for Linux and many other operating systems. It provides safe
handling of the Windows XP, Windows Server 2003, Windows 2000, Windows
Vista, Windows Server 2008 and Windows 7 NTFS file systems. NTFS-3G can
create, remove, rename, move files, directories, hard links, and streams,
it can read and write normal and transparently compressed files, including
streams and sparse files, it can handle special files like symbolic links,
devices, and FIFOs, ACL, extended attributes, moreover it provides full
file access right and ownership support." );
	script_tag( name: "affected", value: "'ntfs-3g' package(s) on Fedora 35." );
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
if(release == "FC35"){
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g", rpm: "ntfs-3g~2021.8.22~1.fc35", rls: "FC35" ) )){
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

