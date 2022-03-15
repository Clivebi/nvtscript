if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882781" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-05 11:55:23 +0530 (Thu, 05 Oct 2017)" );
	script_cve_id( "CVE-2017-14491" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-11 01:29:00 +0000 (Fri, 11 May 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for dnsmasq CESA-2017:2838 centos6" );
	script_tag( name: "summary", value: "Check the version of dnsmasq" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The dnsmasq packages contain Dnsmasq,
a lightweight DNS (Domain Name Server) forwarder and DHCP  (Dynamic Host Configuration Protocol)
server.

Security Fix(es):

  * A heap buffer overflow was found in dnsmasq in the code responsible for
building DNS replies. An attacker could send crafted DNS packets to dnsmasq
which would cause it to crash or, potentially, execute arbitrary code.
(CVE-2017-14491)

Red Hat would like to thank Felix Wilhelm (Google Security Team), Fermin J.
Serna (Google Security Team), Gabriel Campana (Google Security Team), Kevin
Hamacher (Google Security Team), and Ron Bowes (Google Security Team) for
reporting this issue." );
	script_tag( name: "affected", value: "dnsmasq on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:2838" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-October/022554.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "dnsmasq", rpm: "dnsmasq~2.48~18.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dnsmasq-utils", rpm: "dnsmasq-utils~2.48~18.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

