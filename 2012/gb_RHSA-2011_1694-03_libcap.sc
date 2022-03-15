if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-December/msg00016.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870710" );
	script_version( "$Revision: 14114 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-09 10:51:50 +0530 (Mon, 09 Jul 2012)" );
	script_cve_id( "CVE-2011-4099" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "RHSA", value: "2011:1694-03" );
	script_name( "RedHat Update for libcap RHSA-2011:1694-03" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libcap'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "libcap on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The libcap packages provide a library and tools for getting and setting
  POSIX capabilities.

  It was found that capsh did not change into the new root when using the
  '--chroot' option. An application started via the 'capsh --chroot' command
  could use this flaw to escape the chroot restrictions. (CVE-2011-4099)

  This update also fixes the following bug:

  * Previously, the libcap packages did not contain the capsh(1) manual page.
  With this update, the capsh(1) manual page is included. (BZ#730957)

  All libcap users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues." );
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
	if(( res = isrpmvuln( pkg: "libcap", rpm: "libcap~2.16~5.5.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libcap-debuginfo", rpm: "libcap-debuginfo~2.16~5.5.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libcap-devel", rpm: "libcap-devel~2.16~5.5.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

