if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882408" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-10 06:14:52 +0100 (Thu, 10 Mar 2016)" );
	script_cve_id( "CVE-2016-1950" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for nss CESA-2016:0371 centos5" );
	script_tag( name: "summary", value: "Check the version of nss" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set
of libraries designed to support the cross-platform development of security-enabled
client and server applications.

A heap-based buffer overflow flaw was found in the way NSS parsed certain
ASN.1 structures. An attacker could use this flaw to create a specially
crafted certificate which, when parsed by NSS, could cause it to crash, or
execute arbitrary code, using the permissions of the user running an
application compiled against the NSS library. (CVE-2016-1950)

Red Hat would like to thank the Mozilla project for reporting this issue.
Upstream acknowledges Francis Gabriel as the original reporter.

All nss users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to take
effect, all applications linked to the nss library must be restarted, or
the system rebooted." );
	script_tag( name: "affected", value: "nss on CentOS 5" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0371" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-March/021722.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
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
	if(( res = isrpmvuln( pkg: "nss", rpm: "nss~3.19.1~4.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.19.1~4.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-pkcs11-devel", rpm: "nss-pkcs11-devel~3.19.1~4.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.19.1~4.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

