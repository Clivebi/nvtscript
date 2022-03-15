if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881807" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-29 15:25:06 +0530 (Tue, 29 Oct 2013)" );
	script_cve_id( "CVE-2013-5745" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_name( "CentOS Update for vino CESA-2013:1452 centos5" );
	script_tag( name: "affected", value: "vino on CentOS 5" );
	script_tag( name: "insight", value: "Vino is a Virtual Network Computing (VNC) server for GNOME. It allows
remote users to connect to a running GNOME session using VNC.

A denial of service flaw was found in the way Vino handled certain
authenticated requests from clients that were in the deferred state. A
remote attacker could use this flaw to make the vino-server process enter
an infinite loop when processing those incoming requests. (CVE-2013-5745)

All vino users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. The GNOME session must be
restarted (log out, then log back in) for this update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:1452" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-October/019982.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vino'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
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
	if(( res = isrpmvuln( pkg: "vino", rpm: "vino~2.13.5~10.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

