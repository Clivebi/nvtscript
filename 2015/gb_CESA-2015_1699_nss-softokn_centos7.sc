if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882271" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-02 07:00:09 +0200 (Wed, 02 Sep 2015)" );
	script_cve_id( "CVE-2015-2730" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for nss-softokn CESA-2015:1699 centos7" );
	script_tag( name: "summary", value: "Check the version of nss-softokn" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set of libraries designed to support
cross-platform development of security-enabled client and server
applications.

A flaw was found in the way NSS verified certain ECDSA (Elliptic Curve
Digital Signature Algorithm) signatures. Under certain conditions, an
attacker could use this flaw to conduct signature forgery attacks.
(CVE-2015-2730)

Red Hat would like to thank the Mozilla project for reporting this issue.
Upstream acknowledges Watson Ladd as the original reporter of this issue.

All nss-softokn users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "nss-softokn on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1699" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-September/021362.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "nss-softokn", rpm: "nss-softokn~3.16.2.3~13.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-softokn-devel", rpm: "nss-softokn-devel~3.16.2.3~13.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-softokn-freebl", rpm: "nss-softokn-freebl~3.16.2.3~13.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-softokn-freebl-devel", rpm: "nss-softokn-freebl-devel~3.16.2.3~13.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

