if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818411" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-05 01:13:12 +0000 (Sun, 05 Sep 2021)" );
	script_name( "Fedora: Security Advisory for libguestfs (FEDORA-2021-c0235d9d79)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-c0235d9d79" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SLSOBEE7QRLS7S72RUIQFIPNXB5SMAKH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libguestfs'
  package(s) announced via the FEDORA-2021-c0235d9d79 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Libguestfs is a library for accessing and modifying virtual machine
disk images.

Libguestfs uses Linux kernel and qemu code, and can access any type of
guest filesystem that Linux and qemu can, including but not limited
to: ext2/3/4, btrfs, FAT and NTFS, LVM, many different disk partition
schemes, qcow, qcow2, vmdk.

For enhanced features, install:


     libguestfs-forensics  adds filesystem forensics support
          libguestfs-gfs2  adds Global Filesystem (GFS2) support
       libguestfs-hfsplus  adds HFS+ (Mac filesystem) support

 libguestfs-inspect-icons  adds support for inspecting guest icons
        libguestfs-rescue  enhances virt-rescue shell with more tools
         libguestfs-rsync  rsync to/from guest filesystems

           libguestfs-ufs  adds UFS (BSD) support

           libguestfs-xfs  adds XFS support

           libguestfs-zfs  adds ZFS support


For developers:

         libguestfs-devel  C/C++ header files and library

Language bindings:

 libguestfs-gobject-devel  GObject bindings and GObject Introspection



              lua-guestfs  Lua bindings
   ocaml-libguestfs-devel  OCaml bindings
         perl-Sys-Guestfs  Perl bindings

           php-libguestfs  PHP bindings

       python3-libguestfs  Python 3 bindings
          ruby-libguestfs  Ruby bindings

          libguestfs-vala  Vala language bindings" );
	script_tag( name: "affected", value: "'libguestfs' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "libguestfs", rpm: "libguestfs~1.45.7~2.fc34", rls: "FC34" ) )){
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

