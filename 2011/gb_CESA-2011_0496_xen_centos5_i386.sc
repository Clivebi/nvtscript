if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-May/017538.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880508" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2011:0496" );
	script_cve_id( "CVE-2011-1583" );
	script_name( "CentOS Update for xen CESA-2011:0496 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "xen on CentOS 5" );
	script_tag( name: "insight", value: "The xen packages contain administration tools and the xend service for
  managing the kernel-xen kernel for virtualization on Red Hat Enterprise
  Linux.

  It was found that the xc_try_bzip2_decode() and xc_try_lzma_decode() decode
  routines did not correctly check for a possible buffer size overflow in the
  decoding loop. As well, several integer overflow flaws and missing
  error/range checking were found that could lead to an infinite loop. A
  privileged guest user could use these flaws to crash the guest or,
  possibly, execute arbitrary code in the privileged management domain
  (Dom0). (CVE-2011-1583)

  All xen users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. The system must be
  rebooted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~3.0.3~120.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~3.0.3~120.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~3.0.3~120.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

