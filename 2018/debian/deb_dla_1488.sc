if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891488" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3064", "CVE-2018-3066" );
	script_name( "Debian LTS: Security Advisory for mariadb-10.0 (DLA-1488-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-03 00:00:00 +0200 (Mon, 03 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00036.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mariadb-10.0 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
10.0.36-0+deb8u1.

We recommend that you upgrade your mariadb-10.0 packages." );
	script_tag( name: "summary", value: "Several issues have been discovered in the MariaDB database server. The
vulnerabilities are addressed by upgrading MariaDB to the new upstream
version 10.0.36.

CVE-2018-3058

    Easily exploitable vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of MySQL Server accessible data.

CVE-2018-3063

     Easily exploitable vulnerability allows high privileged attacker with
     network access via multiple protocols to compromise MySQL Server.
     Successful attacks of this vulnerability can result in unauthorized
     ability to cause a hang or frequently repeatable crash (complete DOS)
     of MySQL Server.

CVE-2018-3064

    Easily exploitable vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS)
    of MySQL Server as well as unauthorized update, insert or delete access
    to some of MySQL Server accessible data.

CVE-2018-3066

    Difficult to exploit vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of MySQL Server accessible data
    as well as unauthorized read access to a subset of MySQL Server
    accessible data." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-10.0", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-core-10.0", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-common", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-connect-engine-10.0", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-oqgraph-engine-10.0", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-10.0", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-core-10.0", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-test", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-test-10.0", ver: "10.0.36-0+deb8u1", rls: "DEB8" ) )){
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

