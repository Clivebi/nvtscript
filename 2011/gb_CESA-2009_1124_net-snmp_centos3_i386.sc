if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-June/015999.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880819" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2009:1124" );
	script_cve_id( "CVE-2009-1887" );
	script_name( "CentOS Update for net-snmp CESA-2009:1124 centos3 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS3" );
	script_tag( name: "affected", value: "net-snmp on CentOS 3" );
	script_tag( name: "insight", value: "The Simple Network Management Protocol (SNMP) is a protocol used for
  network management.

  A divide-by-zero flaw was discovered in the snmpd daemon. A remote attacker
  could issue a specially-crafted GETBULK request that could crash the snmpd
  daemon. (CVE-2009-1887)

  Note: An attacker must have read access to the SNMP server in order to
  exploit this flaw. In the default configuration, the community name
  'public' grants read-only access. In production deployments, it is
  recommended to change this default community name.

  All net-snmp users should upgrade to these updated packages, which contain
  a backported patch to correct this issue. After installing the update, the
  snmpd and snmptrapd daemons will be restarted automatically." );
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
if(release == "CentOS3"){
	if(( res = isrpmvuln( pkg: "net-snmp", rpm: "net-snmp~5.0.9~2.30E.28", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "net-snmp-devel", rpm: "net-snmp-devel~5.0.9~2.30E.28", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "net-snmp-libs", rpm: "net-snmp-libs~5.0.9~2.30E.28", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "net-snmp-perl", rpm: "net-snmp-perl~5.0.9~2.30E.28", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "net-snmp-utils", rpm: "net-snmp-utils~5.0.9~2.30E.28", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

