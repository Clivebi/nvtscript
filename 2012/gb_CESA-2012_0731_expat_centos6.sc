if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-June/018685.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881114" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:10:51 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-0876", "CVE-2012-1148" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2012:0731" );
	script_name( "CentOS Update for expat CESA-2012:0731 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'expat'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "expat on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Expat is a C library written by James Clark for parsing XML documents.

  A denial of service flaw was found in the implementation of hash arrays in
  Expat. An attacker could use this flaw to make an application using Expat
  consume an excessive amount of CPU time by providing a specially-crafted
  XML file that triggers multiple hash function collisions. To mitigate
  this issue, randomization has been added to the hash function to reduce the
  chance of an attacker successfully causing intentional collisions.
  (CVE-2012-0876)

  A memory leak flaw was found in Expat. If an XML file processed by an
  application linked against Expat triggered a memory re-allocation failure,
  Expat failed to free the previously allocated memory. This could cause the
  application to exit unexpectedly or crash when all available memory is
  exhausted. (CVE-2012-1148)

  All Expat users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, applications using the Expat library must be restarted for the
  update to take effect." );
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
	if(( res = isrpmvuln( pkg: "expat", rpm: "expat~2.0.1~11.el6_2", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "expat-devel", rpm: "expat-devel~2.0.1~11.el6_2", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

