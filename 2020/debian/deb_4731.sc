if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704731" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-14147" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-07-20 03:00:04 +0000 (Mon, 20 Jul 2020)" );
	script_name( "Debian: Security Advisory for redis (DSA-4731-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4731.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4731-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'redis'
  package(s) announced via the DSA-4731-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An integer overflow flaw leading to a stack-based buffer overflow was
discovered in redis, a persistent key-value database. A remote attacker
can use this flaw to cause a denial of service (application crash)." );
	script_tag( name: "affected", value: "'redis' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 5:5.0.3-4+deb10u2.

We recommend that you upgrade your redis packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "redis", ver: "5:5.0.3-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-sentinel", ver: "5:5.0.3-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-server", ver: "5:5.0.3-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-tools", ver: "5:5.0.3-4+deb10u2", rls: "DEB10" ) )){
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

