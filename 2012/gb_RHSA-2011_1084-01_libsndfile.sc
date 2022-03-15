if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-July/msg00019.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870621" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-06-06 10:34:51 +0530 (Wed, 06 Jun 2012)" );
	script_cve_id( "CVE-2011-2696" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "RHSA", value: "2011:1084-01" );
	script_name( "RedHat Update for libsndfile RHSA-2011:1084-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsndfile'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "libsndfile on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The libsndfile packages provide a library for reading and writing sound
  files.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the libsndfile library processed certain Ensoniq PARIS
  Audio Format (PAF) audio files. An attacker could create a
  specially-crafted PAF file that, when opened, could cause an application
  using libsndfile to crash or, potentially, execute arbitrary code with the
  privileges of the user running the application. (CVE-2011-2696)

  Users of libsndfile are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. All running applications
  using libsndfile must be restarted for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "libsndfile", rpm: "libsndfile~1.0.20~3.el6_1.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsndfile-debuginfo", rpm: "libsndfile-debuginfo~1.0.20~3.el6_1.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

