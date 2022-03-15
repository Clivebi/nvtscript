if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871734" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-22 05:44:55 +0100 (Thu, 22 Dec 2016)" );
	script_cve_id( "CVE-2016-1248" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for vim RHSA-2016:2972-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vim'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Vim (Vi IMproved) is an updated and
improved version of the vi editor.

Security Fix(es):

  * A vulnerability was found in vim in how certain modeline options were
treated. An attacker could craft a file that, when opened in vim with
modelines enabled, could execute arbitrary commands with privileges of the
user running vim. (CVE-2016-1248)" );
	script_tag( name: "affected", value: "vim on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2972-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-December/msg00024.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "vim-X11", rpm: "vim-X11~7.4.160~1.el7_3.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-common", rpm: "vim-common~7.4.160~1.el7_3.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-debuginfo", rpm: "vim-debuginfo~7.4.160~1.el7_3.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-enhanced", rpm: "vim-enhanced~7.4.160~1.el7_3.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-filesystem", rpm: "vim-filesystem~7.4.160~1.el7_3.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-minimal", rpm: "vim-minimal~7.4.160~1.el7_3.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "vim-X11", rpm: "vim-X11~7.4.629~5.el6_8.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-common", rpm: "vim-common~7.4.629~5.el6_8.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-debuginfo", rpm: "vim-debuginfo~7.4.629~5.el6_8.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-enhanced", rpm: "vim-enhanced~7.4.629~5.el6_8.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-filesystem", rpm: "vim-filesystem~7.4.629~5.el6_8.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "vim-minimal", rpm: "vim-minimal~7.4.629~5.el6_8.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

