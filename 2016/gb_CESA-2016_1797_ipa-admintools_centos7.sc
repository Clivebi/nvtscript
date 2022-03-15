if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882554" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-09-06 05:38:05 +0200 (Tue, 06 Sep 2016)" );
	script_cve_id( "CVE-2016-5404" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for ipa-admintools CESA-2016:1797 centos7" );
	script_tag( name: "summary", value: "Check the version of ipa-admintools" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Red Hat Identity Management (IdM) is a
centralized authentication, identity management, and authorization solution for
both traditional and cloud-based enterprise environments.

Security Fix(es):

  * An insufficient permission check issue was found in the way IPA server
treats certificate revocation requests. An attacker logged in with the
'retrieve certificate' permission enabled could use this flaw to revoke
certificates, possibly triggering a denial of service attack.
(CVE-2016-5404)

This issue was discovered by Fraser Tweedale (Red Hat)." );
	script_tag( name: "affected", value: "ipa-admintools on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:1797" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-September/022060.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "ipa-admintools", rpm: "ipa-admintools~4.2.0~15.0.1.el7.centos.19", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-client", rpm: "ipa-client~4.2.0~15.0.1.el7.centos.19", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-python", rpm: "ipa-python~4.2.0~15.0.1.el7.centos.19", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server", rpm: "ipa-server~4.2.0~15.0.1.el7.centos.19", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server-dns", rpm: "ipa-server-dns~4.2.0~15.0.1.el7.centos.19", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa-server-trust-ad", rpm: "ipa-server-trust-ad~4.2.0~15.0.1.el7.centos.19", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ipa", rpm: "ipa~4.2.0~15.0.1.el7.centos.19", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

