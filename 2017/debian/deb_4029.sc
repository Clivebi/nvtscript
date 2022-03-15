if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704029" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-8806" );
	script_name( "Debian Security Advisory DSA 4029-1 (postgresql-common - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-09 00:00:00 +0100 (Thu, 09 Nov 2017)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-08 18:42:00 +0000 (Fri, 08 Dec 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "postgresql-common on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 165+deb8u3.

For the stable distribution (stretch), this problem has been fixed in
version 181+deb9u1.

We recommend that you upgrade your postgresql-common packages." );
	script_tag( name: "summary", value: "It was discovered that the pg_ctlcluster, pg_createcluster and
pg_upgradecluster commands handled symbolic links insecurely which could
result in local denial of service by overwriting arbitrary files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "postgresql-common", ver: "181+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-common", ver: "165+deb8u3", rls: "DEB8" ) ) != NULL){
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

