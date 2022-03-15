if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882949" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2018-10-03 17:01:57 +0530 (Wed, 03 Oct 2018)" );
	script_cve_id( "CVE-2018-10873" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for spice-glib CESA-2018:2732 centos6" );
	script_tag( name: "summary", value: "Check the version of spice-glib" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The Simple Protocol for Independent Computing
  Environments (SPICE) is a remote display protocol for virtual environments.
  SPICE users can access a virtualized desktop or server from the local system or
  any system with network access to the server. SPICE is used in Red Hat Enterprise
  Linux for viewing virtualized guests running on the Kernel-based Virtual Machine
  (KVM) hypervisor or on Red Hat Enterprise Virtualization Hypervisors.

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for Simple
Protocol for Independent Computing Environments (SPICE) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of this
widget to access virtual machines using the SPICE protocol.

Security Fix(es):

  * spice: Missing check in demarshal.py:write_validate_array_item() allows
for buffer overflow and denial of service (CVE-2018-10873)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

This issue was discovered by Frediano Ziglio (Red Hat)." );
	script_tag( name: "affected", value: "spice-glib on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:2732" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-September/023024.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "spice-glib", rpm: "spice-glib~0.26~8.el6_10.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-glib-devel", rpm: "spice-glib-devel~0.26~8.el6_10.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk", rpm: "spice-gtk~0.26~8.el6_10.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk-devel", rpm: "spice-gtk-devel~0.26~8.el6_10.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk-python", rpm: "spice-gtk-python~0.26~8.el6_10.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-gtk-tools", rpm: "spice-gtk-tools~0.26~8.el6_10.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

