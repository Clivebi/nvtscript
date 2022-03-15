if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-August/018813.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881471" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-21 11:44:44 +0530 (Tue, 21 Aug 2012)" );
	script_cve_id( "CVE-2011-2896", "CVE-2012-3403", "CVE-2012-3481" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:1180" );
	script_name( "CentOS Update for gimp CESA-2012:1180 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gimp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "gimp on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The GIMP (GNU Image Manipulation Program) is an image composition and
  editing program.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the GIMP's GIF image format plug-in. An attacker could create a
  specially-crafted GIF image file that, when opened, could cause the GIF
  plug-in to crash or, potentially, execute arbitrary code with the
  privileges of the user running the GIMP. (CVE-2012-3481)

  A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch (LZW)
  decompression algorithm implementation used by the GIMP's GIF image format
  plug-in. An attacker could create a specially-crafted GIF image file that,
  when opened, could cause the GIF plug-in to crash or, potentially, execute
  arbitrary code with the privileges of the user running the GIMP.
  (CVE-2011-2896)

  A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL file
  format plug-in. An attacker could create a specially-crafted KiSS palette
  file that, when opened, could cause the CEL plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the GIMP. (CVE-2012-3403)

  Red Hat would like to thank Matthias Weckbecker of the SUSE Security Team
  for reporting the CVE-2012-3481 issue.

  Users of the GIMP are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. The GIMP must be
  restarted for the update to take effect." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "gimp", rpm: "gimp~2.6.9~4.el6_3.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gimp-devel", rpm: "gimp-devel~2.6.9~4.el6_3.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gimp-devel-tools", rpm: "gimp-devel-tools~2.6.9~4.el6_3.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gimp-help-browser", rpm: "gimp-help-browser~2.6.9~4.el6_3.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gimp-libs", rpm: "gimp-libs~2.6.9~4.el6_3.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

