if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871411" );
	script_version( "$Revision: 12497 $" );
	script_cve_id( "CVE-2015-1819" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-07-23 06:26:58 +0200 (Thu, 23 Jul 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for libxml2 RHSA-2015:1419-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libxml2 library is a development toolbox providing the implementation
of various XML standards.

A denial of service flaw was found in the way the libxml2 library parsed
certain XML files. An attacker could provide a specially crafted XML file
that, when parsed by an application using libxml2, could cause that
application to use an excessive amount of memory. (CVE-2015-1819)

This issue was discovered by Florian Weimer of Red Hat Product Security.

This update also fixes the following bug:

This update fixes an error that occurred when running a test case for the
serialization of HTML documents. (BZ#1004513)

Users of libxml2 are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The desktop must be
restarted (log out, then log back in) for this update to take effect." );
	script_tag( name: "affected", value: "libxml2 on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:1419-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-July/msg00030.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
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
	if(( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.6~20.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-debuginfo", rpm: "libxml2-debuginfo~2.7.6~20.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.7.6~20.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.7.6~20.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

