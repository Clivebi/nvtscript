if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-April/015788.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880892" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:0410-01" );
	script_cve_id( "CVE-2009-0846" );
	script_name( "CentOS Update for krb5 CESA-2009:0410-01 centos2 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS2" );
	script_tag( name: "affected", value: "krb5 on CentOS 2" );
	script_tag( name: "insight", value: "Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other using symmetric encryption and a
  trusted third party, the Key Distribution Center (KDC).

  An input validation flaw was found in the ASN.1 (Abstract Syntax Notation
  One) decoder used by MIT Kerberos. A remote attacker could use this flaw to
  crash a network service using the MIT Kerberos library, such as kadmind or
  krb5kdc, by causing it to dereference or free an uninitialized pointer or,
  possibly, execute arbitrary code with the privileges of the user running
  the service. (CVE-2009-0846)

  All krb5 users should upgrade to these updated packages, which contain a
  backported patch to correct this issue. All running services using the MIT
  Kerberos libraries must be restarted for the update to take effect." );
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
if(release == "CentOS2"){
	if(( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.2.2~49", rls: "CentOS2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.2.2~49", rls: "CentOS2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.2.2~49", rls: "CentOS2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.2.2~49", rls: "CentOS2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
