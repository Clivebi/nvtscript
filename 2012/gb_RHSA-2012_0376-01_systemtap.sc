if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2012-March/msg00007.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870574" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-09 10:25:41 +0530 (Fri, 09 Mar 2012)" );
	script_cve_id( "CVE-2012-0875" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:C" );
	script_xref( name: "RHSA", value: "2012:0376-01" );
	script_name( "RedHat Update for systemtap RHSA-2012:0376-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemtap'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_tag( name: "affected", value: "systemtap on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "SystemTap is an instrumentation system for systems running the Linux
  kernel. The system allows developers to write scripts to collect data on
  the operation of the system.

  An invalid pointer read flaw was found in the way SystemTap handled
  malformed debugging information in DWARF format. When SystemTap
  unprivileged mode was enabled, an unprivileged user in the stapusr group
  could use this flaw to crash the system or, potentially, read arbitrary
  kernel memory. Additionally, a privileged user (root, or a member of the
  stapdev group) could trigger this flaw when tricked into instrumenting a
  specially-crafted ELF binary, even when unprivileged mode was not enabled.
  (CVE-2012-0875)

  SystemTap users should upgrade to these updated packages, which contain a
  backported patch to correct this issue." );
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
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "systemtap", rpm: "systemtap~1.6~7.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-debuginfo", rpm: "systemtap-debuginfo~1.6~7.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-initscript", rpm: "systemtap-initscript~1.6~7.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-runtime", rpm: "systemtap-runtime~1.6~7.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-sdt-devel", rpm: "systemtap-sdt-devel~1.6~7.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-server", rpm: "systemtap-server~1.6~7.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-testsuite", rpm: "systemtap-testsuite~1.6~7.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

