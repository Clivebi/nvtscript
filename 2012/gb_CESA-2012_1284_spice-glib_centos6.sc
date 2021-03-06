if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-September/018886.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881506" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-22 11:58:27 +0530 (Sat, 22 Sep 2012)" );
	script_cve_id( "CVE-2012-4425" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2012:1284" );
	script_name( "CentOS Update for spice-glib CESA-2012:1284 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-glib'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "spice-glib on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
  (Simple Protocol for Independent Computing Environments) clients. Both
  Virtual Machine Manager and Virtual Machine Viewer can make use of this
  widget to access virtual machines using the SPICE protocol.

  It was discovered that the spice-gtk setuid helper application,
  spice-client-glib-usb-acl-helper, did not clear the environment variables
  read by the libraries it uses. A local attacker could possibly use this
  flaw to escalate their privileges by setting specific environment variables
  before running the helper application. (CVE-2012-4425)

  Red Hat would like to thank Sebastian Krahmer of the SUSE Security Team for
  reporting this issue.

  All users of spice-gtk are advised to upgrade to these updated packages,
  which contain a backported patch to correct this issue." );
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
	if(( res = isrpmvuln( pkg: "spice-glib", rpm: "spice-glib~0.11~11.el6_3.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-glib-devel", rpm: "spice-glib-devel~0.11~11.el6_3.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk", rpm: "spice-gtk~0.11~11.el6_3.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk-devel", rpm: "spice-gtk-devel~0.11~11.el6_3.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk-python", rpm: "spice-gtk-python~0.11~11.el6_3.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk-tools", rpm: "spice-gtk-tools~0.11~11.el6_3.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

