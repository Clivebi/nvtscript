if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882161" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-0255" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-11 07:35:13 +0200 (Sat, 11 Apr 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for xorg-x11-server-common CESA-2015:0797 centos7" );
	script_tag( name: "summary", value: "Check the version of xorg-x11-server-common" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "X.Org is an open source implementation of the X
  Window System. It provides the basic low-level functionality that full-fledged graphical
  user interfaces are designed upon.

A buffer over-read flaw was found in the way the X.Org server handled
XkbGetGeometry requests. A malicious, authorized client could use this flaw
to disclose portions of the X.Org server memory, or cause the X.Org server
to crash using a specially crafted XkbGetGeometry request. (CVE-2015-0255)

This issue was discovered by Olivier Fourdan of Red Hat.

All xorg-x11-server users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "xorg-x11-server-common on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:0797" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-April/021059.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "xorg-x11-server-common", rpm: "xorg-x11-server-common~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-devel", rpm: "xorg-x11-server-devel~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-source", rpm: "xorg-x11-server-source~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xdmx", rpm: "xorg-x11-server-Xdmx~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xephyr", rpm: "xorg-x11-server-Xephyr~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xnest", rpm: "xorg-x11-server-Xnest~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xorg", rpm: "xorg-x11-server-Xorg~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xvfb", rpm: "xorg-x11-server-Xvfb~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~1.15.0~33.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

