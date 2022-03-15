if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-May/017601.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880519" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0841" );
	script_cve_id( "CVE-2011-1769" );
	script_name( "CentOS Update for systemtap CESA-2011:0841 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemtap'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "systemtap on CentOS 5" );
	script_tag( name: "insight", value: "SystemTap is an instrumentation system for systems running the Linux
  kernel, version 2.6. Developers can write scripts to collect data on the
  operation of the system.

  A divide-by-zero flaw was found in the way SystemTap handled malformed
  debugging information in DWARF format. When SystemTap unprivileged mode was
  enabled, an unprivileged user in the stapusr group could use this flaw to
  crash the system. Additionally, a privileged user (root, or a member of the
  stapdev group) could trigger this flaw when tricked into instrumenting a
  specially-crafted ELF binary, even when unprivileged mode was not enabled.
  (CVE-2011-1769)

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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "systemtap", rpm: "systemtap~1.3~4.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-client", rpm: "systemtap-client~1.3~4.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-initscript", rpm: "systemtap-initscript~1.3~4.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-runtime", rpm: "systemtap-runtime~1.3~4.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-sdt-devel", rpm: "systemtap-sdt-devel~1.3~4.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-server", rpm: "systemtap-server~1.3~4.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "systemtap-testsuite", rpm: "systemtap-testsuite~1.3~4.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

