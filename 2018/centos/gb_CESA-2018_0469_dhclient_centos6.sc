if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882852" );
	script_version( "2021-05-21T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-21 06:00:13 +0200 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-03-14 08:30:33 +0100 (Wed, 14 Mar 2018)" );
	script_cve_id( "CVE-2018-5732", "CVE-2018-5733" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-09 21:14:00 +0000 (Thu, 09 Jan 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for dhclient CESA-2018:0469 centos6" );
	script_tag( name: "summary", value: "Check the version of dhclient" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Dynamic Host Configuration Protocol
(DHCP) is a protocol that allows individual devices on an IP network to get
their own network configuration information, including an IP address, a subnet
mask, and a broadcast address. The dhcp packages provide a relay agent and ISC
DHCP service required to enable and administer DHCP on a network.

Security Fix(es):

  * dhcp: Buffer overflow in dhclient possibly allowing code execution
triggered by malicious server (CVE-2018-5732)

  * dhcp: Reference count overflow in dhcpd allows denial of service
(CVE-2018-5733)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank ISC for reporting these issues. Upstream
acknowledges Felix Wilhelm (Google) as the original reporter of these
issues." );
	script_tag( name: "affected", value: "dhclient on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2018:0469" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-March/022767.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "dhclient", rpm: "dhclient~4.1.1~53.P1.el6.centos.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.1.1~53.P1.el6.centos.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.1.1~53.P1.el6.centos.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.1.1~53.P1.el6.centos.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

