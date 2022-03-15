if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877419" );
	script_version( "2021-07-22T02:00:50+0000" );
	script_cve_id( "CVE-2019-5188", "CVE-2019-5094" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-22 02:00:50 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-12 14:09:00 +0000 (Tue, 12 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-02-02 04:03:10 +0000 (Sun, 02 Feb 2020)" );
	script_name( "Fedora: Security Advisory for e2fsprogs (FEDORA-2020-01ed02451f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-01ed02451f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'e2fsprogs'
  package(s) announced via the FEDORA-2020-01ed02451f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The e2fsprogs package contains a number of utilities for creating,
checking, modifying, and correcting any inconsistencies in second,
third and fourth extended (ext2/ext3/ext4) file systems. E2fsprogs
contains e2fsck (used to repair file system inconsistencies after an
unclean shutdown), mke2fs (used to initialize a partition to contain
an empty ext2 file system), debugfs (used to examine the internal
structure of a file system, to manually repair a corrupted
file system, or to create test cases for e2fsck), tune2fs (used to
modify file system parameters), and most of the other core ext2fs
file system utilities.

You should install the e2fsprogs package if you need to manage the
performance of an ext2, ext3, or ext4 file system." );
	script_tag( name: "affected", value: "'e2fsprogs' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs", rpm: "e2fsprogs~1.44.6~2.fc30", rls: "FC30" ) )){
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

