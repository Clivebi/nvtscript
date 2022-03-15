if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842532" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-13 06:30:22 +0100 (Fri, 13 Nov 2015)" );
	script_cve_id( "CVE-2002-2443", "CVE-2014-5355", "CVE-2015-2694", "CVE-2015-2695", "CVE-2015-2696", "CVE-2015-2698", "CVE-2015-2697" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for krb5 USN-2810-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Kerberos kpasswd
service incorrectly handled certain UDP packets. A remote attacker could possibly
use this issue to cause resource consumption, resulting in a denial of service.
This issue only affected Ubuntu 12.04 LTS. (CVE-2002-2443)

It was discovered that Kerberos incorrectly handled null bytes in certain
data fields. A remote attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 12.04 LTS and Ubuntu
14.04 LTS. (CVE-2014-5355)

It was discovered that the Kerberos kdcpreauth modules incorrectly tracked
certain client requests. A remote attacker could possibly use this issue
to bypass intended preauthentication requirements. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-2694)

It was discovered that Kerberos incorrectly handled certain SPNEGO packets.
A remote attacker could possibly use this issue to cause a denial of
service. (CVE-2015-2695)

It was discovered that Kerberos incorrectly handled certain IAKERB packets.
A remote attacker could possibly use this issue to cause a denial of
service. (CVE-2015-2696, CVE-2015-2698)

It was discovered that Kerberos incorrectly handled certain TGS requests. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2015-2697)" );
	script_tag( name: "affected", value: "krb5 on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2810-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2810-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-otp:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-otp:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-pkinit:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-pkinit:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-user", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssrpc4:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssrpc4:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libk5crypto3:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libk5crypto3:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit9:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit9:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkdb5-7:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkdb5-7:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrad0:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrad0:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5-3:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5-3:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5support0:amd64", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5support0:i386", ver: "1.12.1+dfsg-18ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-otp:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-otp:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-pkinit:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-pkinit:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-user", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssrpc4:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssrpc4:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libk5crypto3:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libk5crypto3:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit9:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit9:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkdb5-7:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkdb5-7:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrad0:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrad0:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5-3:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5-3:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5support0:amd64", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5support0:i386", ver: "1.12+dfsg-2ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-pkinit", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-user", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssrpc4", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libk5crypto3", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit8", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkdb5-6", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5-3", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb53", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5support0", ver: "1.10+dfsg~beta1-2ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-k5tls", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-otp:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-otp:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-pkinit:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-pkinit:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-user", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssrpc4:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgssrpc4:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libk5crypto3:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libk5crypto3:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit9:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit9:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkdb5-8:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkdb5-8:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrad0:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrad0:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5-3:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5-3:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5support0:amd64", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libkrb5support0:i386", ver: "1.13.2+dfsg-2ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

