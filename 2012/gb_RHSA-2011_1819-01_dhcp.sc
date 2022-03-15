if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-December/msg00038.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870728" );
	script_version( "$Revision: 14114 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-09 10:55:47 +0530 (Mon, 09 Jul 2012)" );
	script_cve_id( "CVE-2011-4539" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "RHSA", value: "2011:1819-01" );
	script_name( "RedHat Update for dhcp RHSA-2011:1819-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhcp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "dhcp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The Dynamic Host Configuration Protocol (DHCP) is a protocol that allows
  individual devices on an IP network to get their own network configuration
  information, including an IP address, a subnet mask, and a broadcast
  address.

  A denial of service flaw was found in the way the dhcpd daemon handled DHCP
  request packets when regular expression matching was used in
  '/etc/dhcp/dhcpd.conf'. A remote attacker could use this flaw to crash
  dhcpd. (CVE-2011-4539)

  Users of DHCP should upgrade to these updated packages, which contain a
  backported patch to correct this issue. After installing this update, all
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
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "dhclient", rpm: "dhclient~4.1.1~25.P1.el6_2.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.1.1~25.P1.el6_2.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.1.1~25.P1.el6_2.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-debuginfo", rpm: "dhcp-debuginfo~4.1.1~25.P1.el6_2.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
