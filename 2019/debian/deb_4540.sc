if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704540" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-1547", "CVE-2019-1563" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-10-03 02:00:05 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Debian Security Advisory DSA 4540-1 (openssl1.0 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4540.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4540-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl1.0'
  package(s) announced via the DSA-4540-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two security issues were discovered in OpenSSL: A timing attack against
ECDSA and a padding oracle in PKCS7_dataDecode() and
CMS_decrypt_set1_pkey()." );
	script_tag( name: "affected", value: "'openssl1.0' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 1.0.2t-1~deb9u1.

We recommend that you upgrade your openssl1.0 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0-dev", ver: "1.0.2t-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.2", ver: "1.0.2t-1~deb9u1", rls: "DEB9" ) )){
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

