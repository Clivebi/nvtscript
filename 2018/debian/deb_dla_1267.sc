if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891267" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-1000027" );
	script_name( "Debian LTS: Security Advisory for squid (DLA-1267-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-17 16:15:00 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/02/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "squid on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.7.STABLE9-4.1+deb7u3.

We recommend that you upgrade your squid packages." );
	script_tag( name: "summary", value: "Squid, a high-performance proxy caching server for web clients, has been
found vulnerable to denial of service attacks associated with ESI
response processing and intermediate CA certificate downloading.

CVE-2018-1000027

Incorrect pointer handling resulted in the possibility of a remote
client delivering certain HTTP requests in conjunction with certain
trusted server responses involving the processing of ESI responses or
downloading of intermediate CA certificates to trigger a denial of
service for all clients accessing the squid service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "squid", ver: "2.7.STABLE9-4.1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid-common", ver: "2.7.STABLE9-4.1+deb7u3", rls: "DEB7" ) )){
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

