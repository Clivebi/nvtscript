if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882496" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 16:25:16 +0530 (Fri, 03 Jun 2016)" );
	script_cve_id( "CVE-2016-2108" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for openssl CESA-2016:1137 centos5" );
	script_tag( name: "summary", value: "Check the version of openssl" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the
Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols,
as well as a full-strength general-purpose cryptography library.

Security Fix(es):

  * A flaw was found in the way OpenSSL encoded certain ASN.1 data
structures. An attacker could use this flaw to create a specially crafted
certificate which, when verified or re-encoded by OpenSSL, could cause it
to crash, or execute arbitrary code using the permissions of the user
running an application compiled against the OpenSSL library.
(CVE-2016-2108)

Red Hat would like to thank the OpenSSL project for reporting this issue.
Upstream acknowledges Huzaifa Sidhpurwala (Red Hat), Hanno Bock, and David
Benjamin (Google) as the original reporters." );
	script_tag( name: "affected", value: "openssl on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:1137" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-May/021901.html" );
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
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8e~40.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~0.9.8e~40.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~0.9.8e~40.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

