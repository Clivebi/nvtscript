if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883217" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-10188" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-04-09 03:00:51 +0000 (Thu, 09 Apr 2020)" );
	script_name( "CentOS: Security Advisory for krb5-appl-clients (CESA-2020:1349)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:1349" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-April/035692.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5-appl-clients'
  package(s) announced via the CESA-2020:1349 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The krb5-appl packages contain Kerberos-aware versions of telnet, ftp, rsh,
and rlogin clients and servers. Kerberos is a network authentication system
which allows clients and servers to authenticate to each other using
symmetric encryption and trusted third-party, the Key Distribution Center
(KDC).

Security Fix(es):

  * telnet-server: no bounds checks in nextitem() function allows to remotely
execute arbitrary code (CVE-2020-10188)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'krb5-appl-clients' package(s) on CentOS 6." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "krb5-appl-clients", rpm: "krb5-appl-clients~1.0.1~10.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-appl-servers", rpm: "krb5-appl-servers~1.0.1~10.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-appl", rpm: "krb5-appl~1.0.1~10.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

