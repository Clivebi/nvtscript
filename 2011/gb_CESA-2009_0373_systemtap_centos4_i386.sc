if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-April/015814.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880907" );
	script_version( "2020-11-09T07:42:12+0000" );
	script_tag( name: "last_modification", value: "2020-11-09 07:42:12 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:0373" );
	script_cve_id( "CVE-2009-0784" );
	script_name( "CentOS Update for systemtap CESA-2009:0373 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemtap'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "systemtap on CentOS 4" );
	script_tag( name: "insight", value: "SystemTap is an instrumentation infrastructure for systems running version
  2.6 of the Linux kernel. SystemTap scripts can collect system operations
  data, greatly simplifying information gathering. Collected data can then
  assist in performance measuring, functional testing, and performance and
  function problem diagnosis.

  A race condition was discovered in SystemTap that could allow users in the
  stapusr group to elevate privileges to that of members of the stapdev group
  (and hence root), bypassing directory confinement restrictions and allowing
  them to insert arbitrary SystemTap kernel modules. (CVE-2009-0784)

  Note: This issue was only exploitable if another SystemTap kernel module
  was placed in the 'systemtap/' module directory for the currently running
  kernel.

  Red Hat would like to thank Erik Sj�lund for reporting this issue.

  SystemTap users should upgrade to these updated packages, which contain a
  backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please install the updated packages." );
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
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "systemtap", rpm: "systemtap~0.6.2~2.el4_7", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-runtime", rpm: "systemtap-runtime~0.6.2~2.el4_7", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-testsuite", rpm: "systemtap-testsuite~0.6.2~2.el4_7", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

