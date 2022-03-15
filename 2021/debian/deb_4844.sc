if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704844" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 18:22:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-05 04:00:09 +0000 (Fri, 05 Feb 2021)" );
	script_name( "Debian: Security Advisory for dnsmasq (DSA-4844-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4844.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4844-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4844-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the DSA-4844-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Moshe Kol and Shlomi Oberman of JSOF discovered several
vulnerabilities in dnsmasq, a small caching DNS proxy and DHCP/TFTP
server. They could result in denial of service, cache poisoning or the
execution of arbitrary code." );
	script_tag( name: "affected", value: "'dnsmasq' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2.80-1+deb10u1.

We recommend that you upgrade your dnsmasq packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.80-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.80-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-base-lua", ver: "2.80-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.80-1+deb10u1", rls: "DEB10" ) )){
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

