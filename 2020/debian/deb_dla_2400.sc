if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892400" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-13920" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-15 01:11:00 +0000 (Mon, 15 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-10-08 03:00:19 +0000 (Thu, 08 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for activemq (DLA-2400-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2400-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'activemq'
  package(s) announced via the DLA-2400-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Apache ActiveMQ, a Java message broker, uses
LocateRegistry.createRegistry() to create the JMX RMI registry and binds
the server to the 'jmxrmi' entry. It is possible to connect to the
registry without authentication and call the rebind method to rebind
jmxrmi to something else. If an attacker creates another server to proxy
the original, and bound that, he effectively becomes a man in the middle
and is able to intercept the credentials when an user connects." );
	script_tag( name: "affected", value: "'activemq' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
5.14.3-3+deb9u1.

We recommend that you upgrade your activemq packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "activemq", ver: "5.14.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libactivemq-java", ver: "5.14.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libactivemq-java-doc", ver: "5.14.3-3+deb9u1", rls: "DEB9" ) )){
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

