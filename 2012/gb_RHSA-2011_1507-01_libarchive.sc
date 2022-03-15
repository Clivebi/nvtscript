if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-December/msg00001.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870616" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-09 10:34:18 +0530 (Mon, 09 Jul 2012)" );
	script_cve_id( "CVE-2011-1777", "CVE-2011-1778", "CVE-2010-4666", "CVE-2011-1779" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "RHSA", value: "2011:1507-01" );
	script_name( "RedHat Update for libarchive RHSA-2011:1507-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "libarchive on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The libarchive programming library can create and read several different
  streaming archive formats, including GNU tar and cpio. It can also read ISO
  9660 CD-ROM images.

  Two heap-based buffer overflow flaws were discovered in libarchive. If a
  user were tricked into expanding a specially-crafted ISO 9660 CD-ROM image
  or tar archive with an application using libarchive, it could cause the
  application to crash or, potentially, execute arbitrary code with the
  privileges of the user running the application. (CVE-2011-1777,
  CVE-2011-1778)

  All libarchive users should upgrade to these updated packages, which
  contain backported patches to correct these issues. All running
  applications using libarchive must be restarted for this update to take
  effect." );
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
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "libarchive", rpm: "libarchive~2.8.3~3.el6_1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libarchive-debuginfo", rpm: "libarchive-debuginfo~2.8.3~3.el6_1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

