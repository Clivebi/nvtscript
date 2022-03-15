if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-October/016228.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880824" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2009:1451" );
	script_cve_id( "CVE-2009-3111", "CVE-2003-0967" );
	script_name( "CentOS Update for freeradius CESA-2009:1451 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeradius'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "freeradius on CentOS 5" );
	script_tag( name: "insight", value: "FreeRADIUS is a high-performance and highly configurable free Remote
  Authentication Dial In User Service (RADIUS) server, designed to allow
  centralized authentication and authorization for a network.

  An input validation flaw was discovered in the way FreeRADIUS decoded
  specific RADIUS attributes from RADIUS packets. A remote attacker could use
  this flaw to crash the RADIUS daemon (radiusd) via a specially-crafted
  RADIUS packet. (CVE-2009-3111)

  Users of FreeRADIUS are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, radiusd will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "freeradius", rpm: "freeradius~1.1.3~1.5.el5_4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freeradius-mysql", rpm: "freeradius-mysql~1.1.3~1.5.el5_4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freeradius-postgresql", rpm: "freeradius-postgresql~1.1.3~1.5.el5_4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freeradius-unixODBC", rpm: "freeradius-unixODBC~1.1.3~1.5.el5_4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

