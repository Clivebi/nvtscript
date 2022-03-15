if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-April/015739.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880674" );
	script_version( "2021-09-20T12:48:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 12:48:38 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:0411" );
	script_cve_id( "CVE-2009-0115" );
	script_name( "CentOS Update for device-mapper-multipath CESA-2009:0411 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'device-mapper-multipath'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "device-mapper-multipath on CentOS 5" );
	script_tag( name: "insight", value: "The device-mapper multipath packages provide tools to manage multipath
  devices by issuing instructions to the device-mapper multipath kernel
  module, and by managing the creation and removal of partitions for
  device-mapper devices.

  It was discovered that the multipathd daemon set incorrect permissions on
  the socket used to communicate with command line clients. An unprivileged,
  local user could use this flaw to send commands to multipathd, resulting in
  access disruptions to storage devices accessible via multiple paths and,
  possibly, file system corruption on these devices. (CVE-2009-0115)

  Users of device-mapper-multipath are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. The
  multipathd service must be restarted for the changes to take effect.

  Important: the version of the multipathd daemon in Red Hat Enterprise Linux
  5 has a known issue which may cause a machine to become unresponsive when
  the multipathd service is stopped. This issue is tracked in the Bugzilla
  bug #494582. A link is provided in the References section of this erratum.
  Until this issue is resolved, we recommend restarting the multipathd
  service by issuing the following commands in sequence:

  # killall -KILL multipathd

  # service multipathd restart" );
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
	if(( res = isrpmvuln( pkg: "device-mapper-multipath", rpm: "device-mapper-multipath~0.4.7~23.el5_3.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kpartx", rpm: "kpartx~0.4.7~23.el5_3.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

