if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-April/msg00017.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870648" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-06-06 10:41:04 +0530 (Wed, 06 Jun 2012)" );
	script_cve_id( "CVE-2009-5022" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "RHSA", value: "2011:0452-01" );
	script_name( "RedHat Update for libtiff RHSA-2011:0452-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtiff'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "libtiff on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  A heap-based buffer overflow flaw was found in the way libtiff processed
  certain TIFF image files that were compressed with the JPEG compression
  algorithm. An attacker could use this flaw to create a specially-crafted
  TIFF file that, when opened, would cause an application linked against
  libtiff to crash or, possibly, execute arbitrary code. (CVE-2009-5022)

  All libtiff users should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. All running applications linked
  against libtiff must be restarted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~3.9.4~1.el6_0.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-debuginfo", rpm: "libtiff-debuginfo~3.9.4~1.el6_0.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~3.9.4~1.el6_0.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

