if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-April/017296.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881277" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:15:20 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-0997" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:0428" );
	script_name( "CentOS Update for dhclient CESA-2011:0428 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhclient'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "dhclient on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The Dynamic Host Configuration Protocol (DHCP) is a protocol that allows
  individual devices on an IP network to get their own network configuration
  information, including an IP address, a subnet mask, and a broadcast
  address.

  It was discovered that the DHCP client daemon, dhclient, did not
  sufficiently sanitize certain options provided in DHCP server replies, such
  as the client hostname. A malicious DHCP server could send such an option
  with a specially-crafted value to a DHCP client. If this option's value was
  saved on the client system, and then later insecurely evaluated by a
  process that assumes the option is trusted, it could lead to arbitrary code
  execution with the privileges of that process. (CVE-2011-0997)

  Red Hat would like to thank Sebastian Krahmer of the SuSE Security Team for
  reporting this issue.

  All dhclient users should upgrade to these updated packages, which contain
  a backported patch to correct this issue." );
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
	if(( res = isrpmvuln( pkg: "dhclient", rpm: "dhclient~3.0.5~23.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~3.0.5~23.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~3.0.5~23.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libdhcp4client", rpm: "libdhcp4client~3.0.5~23.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libdhcp4client-devel", rpm: "libdhcp4client-devel~3.0.5~23.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

