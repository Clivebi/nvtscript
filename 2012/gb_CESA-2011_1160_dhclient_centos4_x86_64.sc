if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-August/017693.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881401" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:46:24 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-2748", "CVE-2011-2749" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "CESA", value: "2011:1160" );
	script_name( "CentOS Update for dhclient CESA-2011:1160 centos4 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhclient'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "dhclient on CentOS 4" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The Dynamic Host Configuration Protocol (DHCP) is a protocol that allows
  individual devices on an IP network to get their own network configuration
  information, including an IP address, a subnet mask, and a broadcast
  address.

  Two denial of service flaws were found in the way the dhcpd daemon handled
  certain incomplete request packets. A remote attacker could use these flaws
  to crash dhcpd via a specially-crafted request. (CVE-2011-2748,
  CVE-2011-2749)

  Users of DHCP should upgrade to these updated packages, which contain a
  backported patch to correct these issues. After installing this update, all
  DHCP servers will be restarted automatically." );
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
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "dhclient", rpm: "dhclient~3.0.1~68.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~3.0.1~68.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~3.0.1~68.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

